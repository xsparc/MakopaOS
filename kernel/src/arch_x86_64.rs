use core::arch::{asm, naked_asm};
use core::cell::UnsafeCell;
use core::mem::{offset_of, size_of};
use core::ptr;
use core::slice;

use makopa_address_space::{
    AddressSpaceBackend, AddressSpaceOwner, BOOTSTRAP_PAGE_TABLE_FRAMES, BUILD_LINKS,
    BootstrapBudget, DOUBLE_FAULT_STACK_BASE, DOUBLE_FAULT_STACK_GUARD_LOWER,
    DOUBLE_FAULT_STACK_GUARD_UPPER, DOUBLE_FAULT_STACK_SIZE, DOUBLE_FAULT_STACK_TOP,
    FaultObservation, FrameRole, INVALID_WRITE_TARGET, LifecycleState, LinkSpec, MappingFlags,
    OwnedFrame, PAGE_SIZE, RECOVERY_STACK_BASE, RECOVERY_STACK_GUARD_LOWER,
    RECOVERY_STACK_GUARD_UPPER, RECOVERY_STACK_SIZE, RECOVERY_STACK_TOP, SHARED_PML4_INDICES,
    SUPERVISOR_RW_FLAGS, TASK_FRAME_COUNT, TEMPORARY_WINDOW, USER_STACK, USER_STACK_GUARD_LOWER,
    USER_STACK_GUARD_UPPER, USER_STACK_TOP, USER_TEXT, classify_expected_user_fault,
    construct_address_space, pml1_index, pml2_index, pml3_index, pml4_index, teardown_checked,
    validate_fixed_layout,
};
use makopa_frame_allocator::FrameAllocator;
use x86_64::{VirtAddr, instructions::tlb};

const ENTRY_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const TABLE_LINK_FLAGS: u64 = MappingFlags::PRESENT.union(MappingFlags::WRITABLE).bits();
const EFER_MSR: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;
const FS_BASE_MSR: u32 = 0xc000_0100;
const GS_BASE_MSR: u32 = 0xc000_0101;
const KERNEL_GS_BASE_MSR: u32 = 0xc000_0102;
const CR0_WRITE_PROTECT: u64 = 1 << 16;
const CR4_LA57: u64 = 1 << 12;

const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const USER_DATA_SELECTOR: u16 = 0x1b;
const USER_CODE_SELECTOR: u16 = 0x23;
const TSS_SELECTOR: u16 = 0x28;

const PAGE_FAULT_VECTOR: u8 = 14;
const GENERAL_PROTECTION_VECTOR: u8 = 13;
const DOUBLE_FAULT_VECTOR: u8 = 8;
const DOUBLE_FAULT_IST: u8 = 1;
const TASK_ID: u64 = 1;
const TASK_GENERATION: u64 = 1;

const USER_PROBE: [u8; 15] = [
    0x48, 0xb8, // movabs rax, immediate
    0x00, 0x00, 0x60, 0x00, 0x80, 0x00, 0x00, 0x00, // invalid target
    0xc6, 0x00, 0x01, // mov byte ptr [rax], 1
    0x0f, 0x0b, // ud2 if the write unexpectedly resumes
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationError {
    InvalidLayout,
    UnsupportedCpu,
    UnexpectedLa57,
    InvalidKernelLayout,
    BootstrapPoolExhausted,
    DuplicateMapping,
    MissingMapping,
    InvalidMapping,
    TemporaryWindowBusy,
    TemporaryWindowLeaked,
    FrameAllocation,
    FrameReturn,
    DescriptorState,
    ReachableFrame,
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct RawPageTable {
    entries: [u64; 512],
}

impl RawPageTable {
    const ZERO: Self = Self { entries: [0; 512] };
}

#[repr(C, align(4096))]
struct BootstrapStorage {
    tables: [RawPageTable; BOOTSTRAP_PAGE_TABLE_FRAMES],
}

impl BootstrapStorage {
    const fn new() -> Self {
        Self {
            tables: [RawPageTable::ZERO; BOOTSTRAP_PAGE_TABLE_FRAMES],
        }
    }
}

#[repr(C, align(4096))]
struct PageBytes<const N: usize>([u8; N]);

struct StaticCell<T>(UnsafeCell<T>);

impl<T> StaticCell<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }
}

// SAFETY: OS021 is single-core, enters through one boot path, and keeps
// interrupts disabled outside synchronous exception entry. Each cell has one
// documented owner at a time.
unsafe impl<T> Sync for StaticCell<T> {}

#[used]
#[unsafe(link_section = ".bss.bootstrap_page_tables")]
static BOOTSTRAP_STORAGE: StaticCell<BootstrapStorage> = StaticCell::new(BootstrapStorage::new());

#[used]
#[unsafe(link_section = ".bss.transition_stack")]
static TRANSITION_STACK: StaticCell<PageBytes<4096>> = StaticCell::new(PageBytes([0; 4096]));

#[used]
#[unsafe(link_section = ".bss.recovery_stack")]
static RECOVERY_STACK: StaticCell<PageBytes<{ RECOVERY_STACK_SIZE as usize }>> =
    StaticCell::new(PageBytes([0; RECOVERY_STACK_SIZE as usize]));

#[used]
#[unsafe(link_section = ".bss.double_fault_stack")]
static DOUBLE_FAULT_STACK: StaticCell<PageBytes<{ DOUBLE_FAULT_STACK_SIZE as usize }>> =
    StaticCell::new(PageBytes([0; DOUBLE_FAULT_STACK_SIZE as usize]));

#[derive(Clone, Copy)]
struct RecoveryState {
    root: u64,
    temporary_pte: u64,
    pool_used: usize,
    ready: bool,
}

impl RecoveryState {
    const fn new() -> Self {
        Self {
            root: 0,
            temporary_pte: 0,
            pool_used: 0,
            ready: false,
        }
    }
}

#[unsafe(link_section = ".bss.recovery_state")]
static RECOVERY_STATE: StaticCell<RecoveryState> = StaticCell::new(RecoveryState::new());

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x07,
            type_attributes: 0x8e,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, align(16))]
struct DescriptorState {
    gdt: [u64; 7],
    tss: [u8; 104],
    idt: [IdtEntry; 256],
}

impl DescriptorState {
    const fn new() -> Self {
        Self {
            gdt: [0; 7],
            tss: [0; 104],
            idt: [IdtEntry::MISSING; 256],
        }
    }
}

#[unsafe(link_section = ".bss.descriptor_state")]
static DESCRIPTORS: StaticCell<DescriptorState> = StaticCell::new(DescriptorState::new());

#[derive(Clone, Copy)]
struct ActiveContext {
    present: bool,
    task: u64,
    task_root: u64,
    recovery_root: u64,
    recovery_stack: u64,
    continuation: u64,
}

impl ActiveContext {
    const fn new() -> Self {
        Self {
            present: false,
            task: 0,
            task_root: 0,
            recovery_root: 0,
            recovery_stack: 0,
            continuation: 0,
        }
    }
}

#[unsafe(link_section = ".bss.active_context")]
static ACTIVE_CONTEXT: StaticCell<ActiveContext> = StaticCell::new(ActiveContext::new());

#[unsafe(link_section = ".data.task_owner")]
static TASK_OWNER: StaticCell<Option<AddressSpaceOwner>> = StaticCell::new(None);

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(C)]
struct SavedRegisters {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HardwareExceptionPrefix {
    error_code: u64,
    instruction_pointer: u64,
    code_selector: u64,
    flags: u64,
}

#[derive(Clone, Copy)]
struct ParsedExceptionFrame {
    prefix: HardwareExceptionPrefix,
    user_stack_pointer: Option<u64>,
    user_stack_selector: Option<u64>,
}

const _: () = assert!(size_of::<RawPageTable>() == PAGE_SIZE as usize);
const _: () = assert!(size_of::<SavedRegisters>() == 15 * 8);
const _: () = assert!(offset_of!(SavedRegisters, rax) == 0);
const _: () = assert!(offset_of!(SavedRegisters, r15) == 14 * 8);
const _: () = assert!(size_of::<HardwareExceptionPrefix>() == 4 * 8);
const _: () = assert!(offset_of!(HardwareExceptionPrefix, error_code) == 0);
const _: () = assert!(offset_of!(HardwareExceptionPrefix, code_selector) == 2 * 8);
const _: () = assert!(size_of::<IdtEntry>() == 16);
const _: () = assert!(size_of::<DescriptorState>().is_multiple_of(16));

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
}

struct BootstrapBuilder {
    budget: BootstrapBudget,
}

impl BootstrapBuilder {
    unsafe fn new() -> Self {
        // SAFETY: called once before the bootstrap pool is reachable from any
        // owned CR3. The pool is image-owned and page aligned.
        let storage = unsafe { &mut *BOOTSTRAP_STORAGE.0.get() };
        for table in &mut storage.tables {
            table.entries.fill(0);
        }
        Self {
            budget: BootstrapBudget::new(),
        }
    }

    fn pool_base() -> u64 {
        BOOTSTRAP_STORAGE.0.get() as u64
    }

    fn allocate_table(&mut self) -> Result<u64, IsolationError> {
        let index = self
            .budget
            .claim()
            .map_err(|_| IsolationError::BootstrapPoolExhausted)?;
        let address = Self::pool_base() + index as u64 * PAGE_SIZE;
        Ok(address)
    }

    fn validate_table_address(physical: u64) -> Result<(), IsolationError> {
        let base = Self::pool_base();
        let end = base + BOOTSTRAP_PAGE_TABLE_FRAMES as u64 * PAGE_SIZE;
        if physical < base || physical >= end || !physical.is_multiple_of(PAGE_SIZE) {
            return Err(IsolationError::InvalidMapping);
        }
        Ok(())
    }

    unsafe fn table_ref(&self, physical: u64) -> Result<&RawPageTable, IsolationError> {
        Self::validate_table_address(physical)?;
        // SAFETY: bootstrap pages are identity mapped by ADR-0001 while the
        // tables are constructed, and each address names one pool page.
        Ok(unsafe { &*(physical as *const RawPageTable) })
    }

    unsafe fn table_mut(&mut self, physical: u64) -> Result<&mut RawPageTable, IsolationError> {
        Self::validate_table_address(physical)?;
        // SAFETY: bootstrap pages are identity mapped by ADR-0001 while the
        // tables are constructed, and each address names one pool page.
        Ok(unsafe { &mut *(physical as *mut RawPageTable) })
    }

    unsafe fn ensure_child(&mut self, parent: u64, index: usize) -> Result<u64, IsolationError> {
        let existing = unsafe { self.table_mut(parent)? }.entries[index];
        if existing & MappingFlags::PRESENT.bits() != 0 {
            return Ok(existing & ENTRY_ADDRESS_MASK);
        }
        let child = self.allocate_table()?;
        unsafe { self.table_mut(parent)? }.entries[index] = child | TABLE_LINK_FLAGS;
        Ok(child)
    }

    unsafe fn leaf_slot(
        &mut self,
        root: u64,
        virtual_address: u64,
    ) -> Result<(u64, usize), IsolationError> {
        let pml3 = unsafe { self.ensure_child(root, pml4_index(virtual_address))? };
        let pml2 = unsafe { self.ensure_child(pml3, pml3_index(virtual_address))? };
        let pml1 = unsafe { self.ensure_child(pml2, pml2_index(virtual_address))? };
        Ok((pml1, pml1_index(virtual_address)))
    }

    unsafe fn map_page(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        flags: MappingFlags,
    ) -> Result<(), IsolationError> {
        if !virtual_address.is_multiple_of(PAGE_SIZE) || !physical_address.is_multiple_of(PAGE_SIZE)
        {
            return Err(IsolationError::InvalidMapping);
        }
        let (leaf, index) = unsafe { self.leaf_slot(root, virtual_address)? };
        let entry = &mut unsafe { self.table_mut(leaf)? }.entries[index];
        if *entry & MappingFlags::PRESENT.bits() != 0 {
            return Err(IsolationError::DuplicateMapping);
        }
        *entry = physical_address | flags.bits();
        Ok(())
    }

    unsafe fn map_range(
        &mut self,
        root: u64,
        virtual_start: u64,
        physical_start: u64,
        byte_length: u64,
        flags: MappingFlags,
    ) -> Result<(), IsolationError> {
        if byte_length == 0
            || !virtual_start.is_multiple_of(PAGE_SIZE)
            || !physical_start.is_multiple_of(PAGE_SIZE)
            || !byte_length.is_multiple_of(PAGE_SIZE)
        {
            return Err(IsolationError::InvalidKernelLayout);
        }
        let pages = byte_length / PAGE_SIZE;
        for page in 0..pages {
            let offset = page
                .checked_mul(PAGE_SIZE)
                .ok_or(IsolationError::InvalidKernelLayout)?;
            unsafe {
                self.map_page(root, virtual_start + offset, physical_start + offset, flags)?;
            }
        }
        Ok(())
    }

    unsafe fn entry_for(&self, root: u64, address: u64) -> Option<u64> {
        let pml4 = unsafe { self.table_ref(root).ok()? }.entries[pml4_index(address)];
        let pml3_address = present_address(pml4)?;
        let pml3 = unsafe { self.table_ref(pml3_address).ok()? }.entries[pml3_index(address)];
        let pml2_address = present_address(pml3)?;
        let pml2 = unsafe { self.table_ref(pml2_address).ok()? }.entries[pml2_index(address)];
        let pml1_address = present_address(pml2)?;
        Some(unsafe { self.table_ref(pml1_address).ok()? }.entries[pml1_index(address)])
    }
}

fn present_address(entry: u64) -> Option<u64> {
    (entry & MappingFlags::PRESENT.bits() != 0).then_some(entry & ENTRY_ADDRESS_MASK)
}

fn linker_address(symbol: *const u8) -> u64 {
    let mut address = symbol as u64;
    // The linker intentionally aliases adjacent boundary symbols. Passing the
    // numeric value through an empty architecture barrier prevents the
    // optimizer from applying distinct-object pointer provenance to those
    // linker-defined addresses before their equality is checked.
    unsafe {
        asm!(
            "/* {address} */",
            address = inout(reg) address,
            options(nomem, nostack, preserves_flags)
        );
    }
    address
}

fn checked_range(start: u64, end: u64) -> Result<u64, IsolationError> {
    if !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) || end <= start {
        return Err(IsolationError::InvalidKernelLayout);
    }
    end.checked_sub(start)
        .ok_or(IsolationError::InvalidKernelLayout)
}

pub unsafe fn prepare_recovery_context() -> Result<(), IsolationError> {
    validate_fixed_layout().map_err(|_| IsolationError::InvalidLayout)?;
    validate_cpu_state()?;

    let text_start = linker_address(ptr::addr_of!(__text_start));
    let text_end = linker_address(ptr::addr_of!(__text_end));
    let rodata_start = linker_address(ptr::addr_of!(__rodata_start));
    let rodata_end = linker_address(ptr::addr_of!(__rodata_end));
    let data_start = linker_address(ptr::addr_of!(__data_start));
    let data_end = linker_address(ptr::addr_of!(__data_end));
    let bss_start = linker_address(ptr::addr_of!(__bss_start));
    let bss_end = linker_address(ptr::addr_of!(__bss_end));
    let kernel_start = linker_address(ptr::addr_of!(__kernel_start));
    let kernel_end = linker_address(ptr::addr_of!(__kernel_end));
    if kernel_start != text_start
        || text_end != rodata_start
        || rodata_end != data_start
        || data_end != bss_start
        || bss_end != kernel_end
    {
        return Err(IsolationError::InvalidKernelLayout);
    }

    let mut builder = unsafe { BootstrapBuilder::new() };
    let root = builder.allocate_table()?;
    unsafe {
        builder.map_range(
            root,
            text_start,
            text_start,
            checked_range(text_start, text_end)?,
            makopa_address_space::SUPERVISOR_RX_FLAGS,
        )?;
        builder.map_range(
            root,
            rodata_start,
            rodata_start,
            checked_range(rodata_start, rodata_end)?,
            makopa_address_space::SUPERVISOR_R_FLAGS,
        )?;
        builder.map_range(
            root,
            data_start,
            data_start,
            checked_range(data_start, data_end)?,
            SUPERVISOR_RW_FLAGS,
        )?;
        builder.map_range(
            root,
            bss_start,
            bss_start,
            checked_range(bss_start, bss_end)?,
            SUPERVISOR_RW_FLAGS,
        )?;
    }

    let recovery_physical = RECOVERY_STACK.0.get() as u64;
    let double_fault_physical = DOUBLE_FAULT_STACK.0.get() as u64;
    if !recovery_physical.is_multiple_of(PAGE_SIZE)
        || !double_fault_physical.is_multiple_of(PAGE_SIZE)
    {
        return Err(IsolationError::InvalidKernelLayout);
    }
    unsafe {
        builder.map_range(
            root,
            RECOVERY_STACK_BASE,
            recovery_physical,
            RECOVERY_STACK_SIZE,
            SUPERVISOR_RW_FLAGS,
        )?;
        builder.map_range(
            root,
            DOUBLE_FAULT_STACK_BASE,
            double_fault_physical,
            DOUBLE_FAULT_STACK_SIZE,
            SUPERVISOR_RW_FLAGS,
        )?;
    }
    let (temporary_leaf, temporary_index) = unsafe { builder.leaf_slot(root, TEMPORARY_WINDOW)? };
    let temporary_pte = temporary_leaf + temporary_index as u64 * 8;

    verify_recovery_layout(&builder, root, temporary_pte)?;
    enable_protection_bits();

    let state = unsafe { &mut *RECOVERY_STATE.0.get() };
    *state = RecoveryState {
        root,
        temporary_pte,
        pool_used: builder.budget.used(),
        ready: true,
    };
    Ok(())
}

fn verify_recovery_layout(
    builder: &BootstrapBuilder,
    root: u64,
    temporary_pte: u64,
) -> Result<(), IsolationError> {
    let checks = [
        (RECOVERY_STACK_BASE, SUPERVISOR_RW_FLAGS),
        (RECOVERY_STACK_TOP - PAGE_SIZE, SUPERVISOR_RW_FLAGS),
        (DOUBLE_FAULT_STACK_BASE, SUPERVISOR_RW_FLAGS),
        (DOUBLE_FAULT_STACK_TOP - PAGE_SIZE, SUPERVISOR_RW_FLAGS),
    ];
    for (address, flags) in checks {
        let entry =
            unsafe { builder.entry_for(root, address) }.ok_or(IsolationError::MissingMapping)?;
        let observed = entry
            & (MappingFlags::PRESENT
                .union(MappingFlags::WRITABLE)
                .union(MappingFlags::USER_ACCESSIBLE)
                .union(MappingFlags::NO_EXECUTE))
            .bits();
        if observed != flags.bits() {
            return Err(IsolationError::InvalidMapping);
        }
    }
    for guard in [
        RECOVERY_STACK_GUARD_LOWER,
        RECOVERY_STACK_GUARD_UPPER,
        DOUBLE_FAULT_STACK_GUARD_LOWER,
        DOUBLE_FAULT_STACK_GUARD_UPPER,
    ] {
        if unsafe { builder.entry_for(root, guard) }.unwrap_or(0) & MappingFlags::PRESENT.bits()
            != 0
        {
            return Err(IsolationError::InvalidMapping);
        }
    }
    if unsafe { *(temporary_pte as *const u64) } != 0 {
        return Err(IsolationError::TemporaryWindowBusy);
    }
    let root_table = unsafe { builder.table_ref(root)? };
    if root_table.entries[0] & MappingFlags::USER_ACCESSIBLE.bits() != 0
        || root_table.entries[510] & MappingFlags::USER_ACCESSIBLE.bits() != 0
        || root_table.entries[511] & MappingFlags::USER_ACCESSIBLE.bits() != 0
    {
        return Err(IsolationError::InvalidMapping);
    }
    Ok(())
}

fn validate_cpu_state() -> Result<(), IsolationError> {
    let highest_extended = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if highest_extended < 0x8000_0001 {
        return Err(IsolationError::UnsupportedCpu);
    }
    let features = core::arch::x86_64::__cpuid(0x8000_0001);
    if features.edx & (1 << 20) == 0 {
        return Err(IsolationError::UnsupportedCpu);
    }
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if cr4 & CR4_LA57 != 0 {
        return Err(IsolationError::UnexpectedLa57);
    }
    Ok(())
}

fn enable_protection_bits() {
    let mut efer = unsafe { read_msr(EFER_MSR) };
    efer |= EFER_NXE;
    unsafe { write_msr(EFER_MSR, efer) };

    let mut cr0: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= CR0_WRITE_PROTECT;
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
    }
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack)
        );
    }
}

pub unsafe fn activate_recovery_context() -> ! {
    let state = unsafe { *RECOVERY_STATE.0.get() };
    if !state.ready || state.root == 0 || state.pool_used > BOOTSTRAP_PAGE_TABLE_FRAMES {
        crate::kernel_failure("recovery context not ready")
    }
    let transition_top = TRANSITION_STACK.0.get() as u64 + PAGE_SIZE;
    unsafe {
        makopa_switch_to_recovery(
            state.root,
            RECOVERY_STACK_TOP,
            isolation_entry as *const () as u64,
            transition_top,
        )
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_switch_to_recovery(
    _root: u64,
    _recovery_stack: u64,
    _continuation: u64,
    _transition_stack: u64,
) -> ! {
    naked_asm!(
        "mov rsp, rcx",
        "and rsp, -16",
        "mov cr3, rdi",
        "mov rsp, rsi",
        "and rsp, -16",
        "xor rbp, rbp",
        "jmp rdx",
    )
}

extern "sysv64" fn isolation_entry() -> ! {
    let state = unsafe { *RECOVERY_STATE.0.get() };
    if read_cr3() != state.root {
        crate::kernel_failure("recovery root switch")
    }
    if install_descriptor_tables().is_err() {
        crate::kernel_failure("descriptor tables")
    }

    let allocator = unsafe { crate::frame_allocator() };
    let mut backend = KernelBackend { allocator };
    let mut owner = match construct_address_space(TASK_GENERATION, &mut backend) {
        Ok(owner) => owner,
        Err(_) => crate::kernel_failure("address-space construction"),
    };
    if owner.activate().is_err() {
        crate::kernel_failure("address-space activation")
    }
    let task_root = owner.root().unwrap_or(0);
    if task_root == 0 {
        crate::kernel_failure("task root missing")
    }

    let context = unsafe { &mut *ACTIVE_CONTEXT.0.get() };
    *context = ActiveContext {
        present: true,
        task: TASK_ID,
        task_root,
        recovery_root: state.root,
        recovery_stack: RECOVERY_STACK_TOP,
        continuation: isolation_continuation as *const () as u64,
    };
    unsafe {
        *TASK_OWNER.0.get() = Some(owner);
        makopa_enter_user(task_root, USER_TEXT, USER_STACK_TOP)
    }
}

extern "sysv64" fn isolation_continuation() -> ! {
    let state = unsafe { *RECOVERY_STATE.0.get() };
    if read_cr3() != state.root {
        crate::kernel_failure("recovery root restore")
    }
    let owner = unsafe { &mut *TASK_OWNER.0.get() }
        .take()
        .unwrap_or_else(|| crate::kernel_failure("task owner missing"));
    let mut owner = owner;
    if owner.recover().is_err() {
        crate::kernel_failure("task recovery state")
    }
    let allocator = unsafe { crate::frame_allocator() };
    let mut backend = KernelBackend { allocator };
    let dead = match teardown_checked(owner, &mut backend) {
        Ok(owner) => owner,
        Err(_) => crate::kernel_failure("address-space teardown"),
    };
    if dead.state() != LifecycleState::Dead || !dead.ledger().is_empty() {
        crate::kernel_failure("address-space ownership remains")
    }
    unsafe {
        *ACTIVE_CONTEXT.0.get() = ActiveContext::new();
    }
    crate::isolation_success()
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_enter_user(
    _task_root: u64,
    _instruction_pointer: u64,
    _stack_pointer: u64,
) -> ! {
    naked_asm!(
        "mov cr3, rdi",
        "mov ax, {user_data}",
        "mov ds, ax",
        "mov es, ax",
        "xor eax, eax",
        "mov fs, ax",
        "mov gs, ax",
        "push {user_data}",
        "push rdx",
        "push 0x2",
        "push {user_code}",
        "push rsi",
        "iretq",
        user_data = const USER_DATA_SELECTOR,
        user_code = const USER_CODE_SELECTOR,
    )
}

fn install_descriptor_tables() -> Result<(), IsolationError> {
    let descriptors = unsafe { &mut *DESCRIPTORS.0.get() };
    descriptors.gdt.fill(0);
    descriptors.tss.fill(0);
    descriptors.idt.fill(IdtEntry::MISSING);

    descriptors.gdt[1] = 0x00af_9a00_0000_ffff;
    descriptors.gdt[2] = 0x00cf_9200_0000_ffff;
    descriptors.gdt[3] = 0x00cf_f200_0000_ffff;
    descriptors.gdt[4] = 0x00af_fa00_0000_ffff;

    write_tss_u64(&mut descriptors.tss, 4, RECOVERY_STACK_TOP);
    write_tss_u64(&mut descriptors.tss, 36, DOUBLE_FAULT_STACK_TOP);
    write_tss_u16(&mut descriptors.tss, 102, size_of::<[u8; 104]>() as u16);
    if read_tss_u64(&descriptors.tss, 4) != RECOVERY_STACK_TOP
        || read_tss_u64(&descriptors.tss, 36) != DOUBLE_FAULT_STACK_TOP
        || read_tss_u16(&descriptors.tss, 102) != 104
    {
        return Err(IsolationError::DescriptorState);
    }

    let tss_base = descriptors.tss.as_ptr() as u64;
    let (tss_low, tss_high) = tss_descriptor(tss_base, 103);
    descriptors.gdt[5] = tss_low;
    descriptors.gdt[6] = tss_high;

    descriptors.idt[PAGE_FAULT_VECTOR as usize] =
        IdtEntry::interrupt_gate(makopa_page_fault_trampoline as *const () as u64, 0);
    descriptors.idt[GENERAL_PROTECTION_VECTOR as usize] =
        IdtEntry::interrupt_gate(makopa_general_protection_trampoline as *const () as u64, 0);
    descriptors.idt[DOUBLE_FAULT_VECTOR as usize] = IdtEntry::interrupt_gate(
        makopa_double_fault_trampoline as *const () as u64,
        DOUBLE_FAULT_IST,
    );

    let gdt_pointer = DescriptorTablePointer {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: descriptors.gdt.as_ptr() as u64,
    };
    let idt_pointer = DescriptorTablePointer {
        limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: descriptors.idt.as_ptr() as u64,
    };
    unsafe {
        asm!("lgdt [{}]", in(reg) &gdt_pointer, options(readonly, nostack, preserves_flags));
        asm!(
            "mov ax, {kernel_data}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor eax, eax",
            "mov fs, ax",
            "mov gs, ax",
            "push {kernel_code}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            kernel_data = const KERNEL_DATA_SELECTOR,
            kernel_code = const KERNEL_CODE_SELECTOR,
        );
        asm!("lidt [{}]", in(reg) &idt_pointer, options(readonly, nostack, preserves_flags));
        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nomem, nostack, preserves_flags));
        write_msr(FS_BASE_MSR, 0);
        write_msr(GS_BASE_MSR, 0);
        write_msr(KERNEL_GS_BASE_MSR, 0);
    }
    let task_register: u16;
    unsafe {
        asm!("str {0:x}", out(reg) task_register, options(nomem, nostack, preserves_flags));
    }
    if task_register != TSS_SELECTOR {
        return Err(IsolationError::DescriptorState);
    }
    Ok(())
}

fn write_tss_u64(tss: &mut [u8; 104], offset: usize, value: u64) {
    tss[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_tss_u16(tss: &mut [u8; 104], offset: usize, value: u16) {
    tss[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_tss_u64(tss: &[u8; 104], offset: usize) -> u64 {
    u64::from_le_bytes(tss[offset..offset + 8].try_into().expect("fixed TSS field"))
}

fn read_tss_u16(tss: &[u8; 104], offset: usize) -> u16 {
    u16::from_le_bytes(tss[offset..offset + 2].try_into().expect("fixed TSS field"))
}

fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let low = u64::from(limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89_u64 << 40)
        | (u64::from((limit >> 16) & 0x0f) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

struct KernelBackend<'a> {
    allocator: &'a mut FrameAllocator,
}

impl AddressSpaceBackend for KernelBackend<'_> {
    type Error = IsolationError;

    fn allocate_frame(&mut self, _role: FrameRole) -> Result<u64, Self::Error> {
        self.allocator
            .allocate_frame()
            .map_err(|_| IsolationError::FrameAllocation)
    }

    fn prepare_frame(&mut self, role: FrameRole, frame: u64) -> Result<(), Self::Error> {
        with_temporary_frame(frame, |bytes| {
            bytes.fill(0);
            if role == FrameRole::Root {
                let state = unsafe { *RECOVERY_STATE.0.get() };
                let recovery = unsafe { &*(state.root as *const RawPageTable) };
                let task = page_table_bytes(bytes)?;
                for index in SHARED_PML4_INDICES {
                    task[index] = recovery.entries[index];
                }
            } else if role == FrameRole::Text {
                bytes[..USER_PROBE.len()].copy_from_slice(&USER_PROBE);
            }
            Ok(())
        })
    }

    fn install_link(&mut self, link: LinkSpec, parent: u64, child: u64) -> Result<(), Self::Error> {
        with_temporary_frame(parent, |bytes| {
            let table = page_table_bytes(bytes)?;
            let entry = &mut table[link.entry_index];
            if *entry != 0 {
                return Err(IsolationError::DuplicateMapping);
            }
            *entry = child | link.flags.bits();
            Ok(())
        })
    }

    fn remove_link(&mut self, link: LinkSpec, parent: u64, child: u64) -> Result<(), Self::Error> {
        with_temporary_frame(parent, |bytes| {
            let table = page_table_bytes(bytes)?;
            let entry = &mut table[link.entry_index];
            if *entry & ENTRY_ADDRESS_MASK != child || *entry & MappingFlags::PRESENT.bits() == 0 {
                return Err(IsolationError::MissingMapping);
            }
            *entry = 0;
            Ok(())
        })
    }

    fn clear_shared_entries(&mut self, root: u64) -> Result<(), Self::Error> {
        with_temporary_frame(root, |bytes| {
            let table = page_table_bytes(bytes)?;
            for index in SHARED_PML4_INDICES {
                table[index] = 0;
            }
            Ok(())
        })
    }

    fn clear_temporary_window(&mut self) -> Result<(), Self::Error> {
        let state = unsafe { *RECOVERY_STATE.0.get() };
        let entry = unsafe { &mut *(state.temporary_pte as *mut u64) };
        if *entry == 0 {
            return Ok(());
        }
        *entry = 0;
        tlb::flush(VirtAddr::new(TEMPORARY_WINDOW));
        Err(IsolationError::TemporaryWindowLeaked)
    }

    fn verify_unreachable(&mut self, frames: &[OwnedFrame]) -> Result<(), Self::Error> {
        let state = unsafe { *RECOVERY_STATE.0.get() };
        if read_cr3() != state.root || unsafe { *(state.temporary_pte as *const u64) } != 0 {
            return Err(IsolationError::ReachableFrame);
        }
        for owned in frames {
            if matches!(
                owned.role,
                FrameRole::Root
                    | FrameRole::UserPml3
                    | FrameRole::UserPml2
                    | FrameRole::TextPml1
                    | FrameRole::StackPml1
            ) {
                with_temporary_frame(owned.physical_start, |bytes| {
                    if page_table_bytes(bytes)?.iter().any(|entry| *entry != 0) {
                        return Err(IsolationError::ReachableFrame);
                    }
                    Ok(())
                })?;
            }
        }
        let storage = unsafe { &*BOOTSTRAP_STORAGE.0.get() };
        for table in &storage.tables[..state.pool_used] {
            for entry in table.entries {
                if entry & MappingFlags::PRESENT.bits() != 0
                    && frames
                        .iter()
                        .any(|owned| owned.physical_start == entry & ENTRY_ADDRESS_MASK)
                {
                    return Err(IsolationError::ReachableFrame);
                }
            }
        }
        Ok(())
    }

    fn return_frame(&mut self, frame: OwnedFrame) -> Result<(), Self::Error> {
        self.allocator
            .free_frame(frame.physical_start)
            .map_err(|_| IsolationError::FrameReturn)
    }
}

fn page_table_bytes(bytes: &mut [u8]) -> Result<&mut [u64; 512], IsolationError> {
    if bytes.len() != PAGE_SIZE as usize || !(bytes.as_ptr() as usize).is_multiple_of(8) {
        return Err(IsolationError::InvalidMapping);
    }
    // SAFETY: a page-table view has exactly 512 aligned u64 entries and lives
    // only for the temporary-window closure.
    Ok(unsafe { &mut *(bytes.as_mut_ptr().cast::<[u64; 512]>()) })
}

fn with_temporary_frame<T>(
    frame: u64,
    operation: impl FnOnce(&mut [u8]) -> Result<T, IsolationError>,
) -> Result<T, IsolationError> {
    if frame == 0 || !frame.is_multiple_of(PAGE_SIZE) {
        return Err(IsolationError::InvalidMapping);
    }
    let state = unsafe { *RECOVERY_STATE.0.get() };
    if !state.ready || state.temporary_pte == 0 {
        return Err(IsolationError::TemporaryWindowBusy);
    }
    let entry = unsafe { &mut *(state.temporary_pte as *mut u64) };
    if *entry != 0 {
        return Err(IsolationError::TemporaryWindowBusy);
    }
    *entry = frame | SUPERVISOR_RW_FLAGS.bits();
    tlb::flush(VirtAddr::new(TEMPORARY_WINDOW));
    // SAFETY: the temporary PTE maps exactly one writable page. The slice is
    // scoped to this call and is destroyed before the entry is cleared.
    let result = operation(unsafe {
        slice::from_raw_parts_mut(TEMPORARY_WINDOW as *mut u8, PAGE_SIZE as usize)
    });
    *entry = 0;
    tlb::flush(VirtAddr::new(TEMPORARY_WINDOW));
    result
}

fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & ENTRY_ADDRESS_MASK
}

unsafe fn parse_exception_frame(hardware: *const u64) -> ParsedExceptionFrame {
    // SAFETY: each trampoline passes the hardware frame immediately above its
    // asserted 15-register save area. The first four fields always exist.
    let prefix = unsafe {
        HardwareExceptionPrefix {
            error_code: hardware.add(0).read(),
            instruction_pointer: hardware.add(1).read(),
            code_selector: hardware.add(2).read(),
            flags: hardware.add(3).read(),
        }
    };
    if prefix.code_selector & 3 == 3 {
        ParsedExceptionFrame {
            prefix,
            // SAFETY: an inter-privilege hardware frame includes saved RSP/SS.
            user_stack_pointer: Some(unsafe { hardware.add(4).read() }),
            user_stack_selector: Some(unsafe { hardware.add(5).read() }),
        }
    } else {
        ParsedExceptionFrame {
            prefix,
            user_stack_pointer: None,
            user_stack_selector: None,
        }
    }
}

#[unsafe(no_mangle)]
extern "sysv64" fn makopa_exception_dispatch(
    vector: u64,
    hardware: *const u64,
    fault_address: u64,
) -> ! {
    let frame = unsafe { parse_exception_frame(hardware) };
    if vector != u64::from(PAGE_FAULT_VECTOR)
        || frame.user_stack_pointer.is_none()
        || frame.user_stack_selector != Some(u64::from(USER_DATA_SELECTOR))
        || frame.prefix.instruction_pointer < USER_TEXT
        || frame.prefix.instruction_pointer >= USER_TEXT + PAGE_SIZE
        || frame.prefix.flags & ((1 << 9) | (1 << 10) | (3 << 12)) != 0
    {
        crate::kernel_failure("unexpected exception frame")
    }
    let context = unsafe { *ACTIVE_CONTEXT.0.get() };
    let owner_state = unsafe { &*TASK_OWNER.0.get() }
        .as_ref()
        .map(AddressSpaceOwner::state)
        .unwrap_or(LifecycleState::Dead);
    let observation = FaultObservation {
        expected_task: TASK_ID,
        observed_task: context.task,
        owner_state,
        expected_root: context.task_root,
        current_root: read_cr3(),
        code_selector: frame.prefix.code_selector,
        fault_address,
        error_code: frame.prefix.error_code,
    };
    if !context.present
        || context.recovery_root == 0
        || context.recovery_stack != RECOVERY_STACK_TOP
        || context.continuation == 0
        || classify_expected_user_fault(observation).is_err()
    {
        crate::kernel_failure("user fault classification")
    }
    unsafe {
        makopa_recover_from_user_fault(
            context.recovery_root,
            context.recovery_stack,
            context.continuation,
        )
    }
}

#[unsafe(no_mangle)]
extern "sysv64" fn makopa_double_fault_dispatch(hardware: *const u64) -> ! {
    // The IST-specific path deliberately reads only the common prefix. It
    // never assumes that a CPL-dependent SS:RSP pair follows it and never
    // returns to a potentially exhausted or corrupted stack.
    let prefix = unsafe {
        HardwareExceptionPrefix {
            error_code: hardware.add(0).read(),
            instruction_pointer: hardware.add(1).read(),
            code_selector: hardware.add(2).read(),
            flags: hardware.add(3).read(),
        }
    };
    let _ = prefix;
    crate::kernel_failure("double fault")
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_page_fault_trampoline() -> ! {
    naked_asm!(
        "cld",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rbp",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "lea rsi, [rsp + 120]",
        "mov rdx, cr2",
        "mov edi, 14",
        "and rsp, -16",
        "call {dispatch}",
        "ud2",
        dispatch = sym makopa_exception_dispatch,
    )
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_general_protection_trampoline() -> ! {
    naked_asm!(
        "cld",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rbp",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "lea rsi, [rsp + 120]",
        "xor edx, edx",
        "mov edi, 13",
        "and rsp, -16",
        "call {dispatch}",
        "ud2",
        dispatch = sym makopa_exception_dispatch,
    )
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_double_fault_trampoline() -> ! {
    naked_asm!(
        "cld",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rbp",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "lea rdi, [rsp + 120]",
        "and rsp, -16",
        "call {dispatch}",
        "ud2",
        dispatch = sym makopa_double_fault_dispatch,
    )
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn makopa_recover_from_user_fault(
    _recovery_root: u64,
    _recovery_stack: u64,
    _continuation: u64,
) -> ! {
    naked_asm!(
        "mov cr3, rdi",
        "mov rsp, rsi",
        "and rsp, -16",
        "xor rbp, rbp",
        "jmp rdx",
    )
}

const _: () = assert!(BUILD_LINKS.len() == TASK_FRAME_COUNT - 1);
const _: () = assert!(USER_STACK_GUARD_LOWER + PAGE_SIZE == USER_STACK);
const _: () = assert!(USER_STACK + PAGE_SIZE == USER_STACK_GUARD_UPPER);
const _: () = assert!(INVALID_WRITE_TARGET != USER_TEXT);
