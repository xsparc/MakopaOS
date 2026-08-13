#![no_std]

//! Fixed, host-testable ownership rules for the first MakopaOS address space.
//!
//! Architecture code supplies the page-table editing backend. This crate owns
//! the bounded construction plan, lifecycle, rollback order, stale-token
//! checks, mapping permissions, and exact expected-fault classifier.

use core::fmt;

pub const PAGE_SIZE: u64 = 4096;
pub const BOOTSTRAP_PAGE_TABLE_FRAMES: usize = 32;
pub const TASK_LEDGER_CAPACITY: usize = 16;
pub const TASK_FRAME_COUNT: usize = 7;

pub const USER_TEXT: u64 = 0x0000_0080_0040_0000;
pub const INVALID_WRITE_TARGET: u64 = 0x0000_0080_0060_0000;
pub const USER_STACK_GUARD_LOWER: u64 = 0x0000_0080_007f_f000;
pub const USER_STACK: u64 = 0x0000_0080_0080_0000;
pub const USER_STACK_GUARD_UPPER: u64 = 0x0000_0080_0080_1000;
pub const USER_STACK_TOP: u64 = USER_STACK + PAGE_SIZE;

pub const RECOVERY_STACK_BASE: u64 = 0xffff_ff00_0000_1000;
pub const RECOVERY_STACK_SIZE: u64 = 64 * 1024;
pub const RECOVERY_STACK_TOP: u64 = RECOVERY_STACK_BASE + RECOVERY_STACK_SIZE;
pub const RECOVERY_STACK_GUARD_LOWER: u64 = RECOVERY_STACK_BASE - PAGE_SIZE;
pub const RECOVERY_STACK_GUARD_UPPER: u64 = RECOVERY_STACK_TOP;

pub const DOUBLE_FAULT_STACK_BASE: u64 = 0xffff_ff00_0002_1000;
pub const DOUBLE_FAULT_STACK_SIZE: u64 = 16 * 1024;
pub const DOUBLE_FAULT_STACK_TOP: u64 = DOUBLE_FAULT_STACK_BASE + DOUBLE_FAULT_STACK_SIZE;
pub const DOUBLE_FAULT_STACK_GUARD_LOWER: u64 = DOUBLE_FAULT_STACK_BASE - PAGE_SIZE;
pub const DOUBLE_FAULT_STACK_GUARD_UPPER: u64 = DOUBLE_FAULT_STACK_TOP;

pub const TEMPORARY_WINDOW: u64 = 0xffff_ff80_0000_0000;
pub const USER_PML4_INDEX: usize = 1;
pub const SHARED_PML4_INDICES: [usize; 3] = [0, 510, 511];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapBudget {
    used: usize,
}

impl BootstrapBudget {
    pub const fn new() -> Self {
        Self { used: 0 }
    }

    pub const fn used(self) -> usize {
        self.used
    }

    pub fn claim(&mut self) -> Result<usize, BootstrapBudgetError> {
        if self.used == BOOTSTRAP_PAGE_TABLE_FRAMES {
            return Err(BootstrapBudgetError::Exhausted);
        }
        let index = self.used;
        self.used += 1;
        Ok(index)
    }
}

impl Default for BootstrapBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapBudgetError {
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct MappingFlags(u64);

impl MappingFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const CACHE_DISABLE: Self = Self(1 << 4);
    pub const NO_EXECUTE: Self = Self(1 << 63);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

pub const TABLE_FLAGS: MappingFlags = MappingFlags::PRESENT
    .union(MappingFlags::WRITABLE)
    .union(MappingFlags::USER_ACCESSIBLE);
pub const USER_TEXT_FLAGS: MappingFlags =
    MappingFlags::PRESENT.union(MappingFlags::USER_ACCESSIBLE);
pub const USER_STACK_FLAGS: MappingFlags = MappingFlags::PRESENT
    .union(MappingFlags::WRITABLE)
    .union(MappingFlags::USER_ACCESSIBLE)
    .union(MappingFlags::NO_EXECUTE);
pub const SUPERVISOR_RX_FLAGS: MappingFlags = MappingFlags::PRESENT;
pub const SUPERVISOR_R_FLAGS: MappingFlags = MappingFlags::PRESENT.union(MappingFlags::NO_EXECUTE);
pub const SUPERVISOR_RW_FLAGS: MappingFlags = MappingFlags::PRESENT
    .union(MappingFlags::WRITABLE)
    .union(MappingFlags::NO_EXECUTE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingSpec {
    pub virtual_address: u64,
    pub flags: MappingFlags,
}

pub const USER_MAPPINGS: [MappingSpec; 2] = [
    MappingSpec {
        virtual_address: USER_TEXT,
        flags: USER_TEXT_FLAGS,
    },
    MappingSpec {
        virtual_address: USER_STACK,
        flags: USER_STACK_FLAGS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameRole {
    Root = 0,
    UserPml3 = 1,
    UserPml2 = 2,
    TextPml1 = 3,
    StackPml1 = 4,
    Text = 5,
    Stack = 6,
}

impl FrameRole {
    pub const ALL: [Self; TASK_FRAME_COUNT] = [
        Self::Root,
        Self::UserPml3,
        Self::UserPml2,
        Self::TextPml1,
        Self::StackPml1,
        Self::Text,
        Self::Stack,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(FrameRole::ALL.len() <= TASK_LEDGER_CAPACITY);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkSpec {
    pub parent: FrameRole,
    pub child: FrameRole,
    pub entry_index: usize,
    pub flags: MappingFlags,
}

pub const BUILD_LINKS: [LinkSpec; 6] = [
    LinkSpec {
        parent: FrameRole::Root,
        child: FrameRole::UserPml3,
        entry_index: pml4_index(USER_TEXT),
        flags: TABLE_FLAGS,
    },
    LinkSpec {
        parent: FrameRole::UserPml3,
        child: FrameRole::UserPml2,
        entry_index: pml3_index(USER_TEXT),
        flags: TABLE_FLAGS,
    },
    LinkSpec {
        parent: FrameRole::UserPml2,
        child: FrameRole::TextPml1,
        entry_index: pml2_index(USER_TEXT),
        flags: TABLE_FLAGS,
    },
    LinkSpec {
        parent: FrameRole::UserPml2,
        child: FrameRole::StackPml1,
        entry_index: pml2_index(USER_STACK),
        flags: TABLE_FLAGS,
    },
    LinkSpec {
        parent: FrameRole::TextPml1,
        child: FrameRole::Text,
        entry_index: pml1_index(USER_TEXT),
        flags: USER_TEXT_FLAGS,
    },
    LinkSpec {
        parent: FrameRole::StackPml1,
        child: FrameRole::Stack,
        entry_index: pml1_index(USER_STACK),
        flags: USER_STACK_FLAGS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    NonCanonical,
    Unaligned,
    Overlap,
    WrongOrder,
    WrongPml4Slot,
    WritableExecutable,
    MissingUserAccess,
    GuardMapped,
}

pub fn validate_fixed_layout() -> Result<(), LayoutError> {
    let addresses = [
        USER_TEXT,
        INVALID_WRITE_TARGET,
        USER_STACK_GUARD_LOWER,
        USER_STACK,
        USER_STACK_GUARD_UPPER,
        RECOVERY_STACK_BASE,
        RECOVERY_STACK_GUARD_LOWER,
        RECOVERY_STACK_GUARD_UPPER,
        DOUBLE_FAULT_STACK_BASE,
        DOUBLE_FAULT_STACK_GUARD_LOWER,
        DOUBLE_FAULT_STACK_GUARD_UPPER,
        TEMPORARY_WINDOW,
    ];
    for address in addresses {
        if !is_canonical_48(address) {
            return Err(LayoutError::NonCanonical);
        }
        if address % PAGE_SIZE != 0 {
            return Err(LayoutError::Unaligned);
        }
    }
    if pml4_index(USER_TEXT) != USER_PML4_INDEX || pml4_index(USER_STACK) != USER_PML4_INDEX {
        return Err(LayoutError::WrongPml4Slot);
    }
    if pml4_index(RECOVERY_STACK_BASE) != 510
        || pml4_index(DOUBLE_FAULT_STACK_BASE) != 510
        || pml4_index(TEMPORARY_WINDOW) != 511
    {
        return Err(LayoutError::WrongPml4Slot);
    }
    if !(USER_TEXT < INVALID_WRITE_TARGET
        && INVALID_WRITE_TARGET < USER_STACK_GUARD_LOWER
        && USER_STACK_GUARD_LOWER < USER_STACK
        && USER_STACK < USER_STACK_GUARD_UPPER)
    {
        return Err(LayoutError::WrongOrder);
    }
    let page_addresses = [
        USER_TEXT,
        INVALID_WRITE_TARGET,
        USER_STACK_GUARD_LOWER,
        USER_STACK,
        USER_STACK_GUARD_UPPER,
        RECOVERY_STACK_GUARD_LOWER,
        RECOVERY_STACK_BASE,
        RECOVERY_STACK_GUARD_UPPER,
        DOUBLE_FAULT_STACK_GUARD_LOWER,
        DOUBLE_FAULT_STACK_BASE,
        DOUBLE_FAULT_STACK_GUARD_UPPER,
        TEMPORARY_WINDOW,
    ];
    for (index, left) in page_addresses.iter().enumerate() {
        for right in &page_addresses[index + 1..] {
            if left == right {
                return Err(LayoutError::Overlap);
            }
        }
    }
    for mapping in USER_MAPPINGS {
        if !mapping.flags.contains(MappingFlags::USER_ACCESSIBLE) {
            return Err(LayoutError::MissingUserAccess);
        }
        if mapping.flags.contains(MappingFlags::WRITABLE)
            && !mapping.flags.contains(MappingFlags::NO_EXECUTE)
        {
            return Err(LayoutError::WritableExecutable);
        }
    }
    if USER_MAPPINGS.iter().any(|mapping| {
        matches!(
            mapping.virtual_address,
            INVALID_WRITE_TARGET
                | USER_STACK_GUARD_LOWER
                | USER_STACK_GUARD_UPPER
                | RECOVERY_STACK_GUARD_LOWER
                | RECOVERY_STACK_GUARD_UPPER
                | DOUBLE_FAULT_STACK_GUARD_LOWER
                | DOUBLE_FAULT_STACK_GUARD_UPPER
        )
    }) {
        return Err(LayoutError::GuardMapped);
    }
    Ok(())
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

pub const fn pml4_index(address: u64) -> usize {
    ((address >> 39) & 0x1ff) as usize
}

pub const fn pml3_index(address: u64) -> usize {
    ((address >> 30) & 0x1ff) as usize
}

pub const fn pml2_index(address: u64) -> usize {
    ((address >> 21) & 0x1ff) as usize
}

pub const fn pml1_index(address: u64) -> usize {
    ((address >> 12) & 0x1ff) as usize
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Building,
    Inactive,
    Active,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedFrame {
    pub role: FrameRole,
    pub physical_start: u64,
}

const EMPTY_FRAME: OwnedFrame = OwnedFrame {
    role: FrameRole::Root,
    physical_start: 0,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrameLedger {
    frames: [OwnedFrame; TASK_LEDGER_CAPACITY],
    len: usize,
}

impl fmt::Debug for FrameLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.as_slice().iter())
            .finish()
    }
}

impl FrameLedger {
    pub const fn new() -> Self {
        Self {
            frames: [EMPTY_FRAME; TASK_LEDGER_CAPACITY],
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[OwnedFrame] {
        &self.frames[..self.len]
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_owned(&mut self, frame: OwnedFrame) -> Result<(), OwnerError> {
        if self.len == TASK_LEDGER_CAPACITY {
            return Err(OwnerError::LedgerFull);
        }
        self.frames[self.len] = frame;
        self.len += 1;
        Ok(())
    }

    fn validate_latest(&self) -> Result<(), OwnerError> {
        let Some((frame, previous)) = self.as_slice().split_last() else {
            return Ok(());
        };
        if !frame.physical_start.is_multiple_of(PAGE_SIZE) {
            return Err(OwnerError::InvalidFrame);
        }
        if previous
            .iter()
            .any(|owned| owned.physical_start == frame.physical_start || owned.role == frame.role)
        {
            return Err(OwnerError::DuplicateFrame);
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<OwnedFrame> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let frame = self.frames[self.len];
        self.frames[self.len] = EMPTY_FRAME;
        Some(frame)
    }

    pub fn frame_for(&self, role: FrameRole) -> Option<u64> {
        self.as_slice()
            .iter()
            .find(|frame| frame.role == role)
            .map(|frame| frame.physical_start)
    }
}

impl Default for FrameLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerError {
    InvalidGeneration,
    InvalidFrame,
    DuplicateFrame,
    LedgerFull,
    WrongState,
    RootNotOwned,
    StaleOwner,
    StaleToken,
    InvalidTokenAddress,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AddressSpaceOwner {
    generation: u64,
    generation_live: bool,
    state: LifecycleState,
    root: Option<u64>,
    ledger: FrameLedger,
}

impl AddressSpaceOwner {
    pub fn begin(generation: u64) -> Result<Self, OwnerError> {
        if generation == 0 {
            return Err(OwnerError::InvalidGeneration);
        }
        Ok(Self {
            generation,
            generation_live: true,
            state: LifecycleState::Building,
            root: None,
            ledger: FrameLedger::new(),
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    pub const fn root(&self) -> Option<u64> {
        self.root
    }

    pub const fn ledger(&self) -> &FrameLedger {
        &self.ledger
    }

    fn record_frame(&mut self, frame: OwnedFrame) -> Result<(), OwnerError> {
        if self.state != LifecycleState::Building || !self.generation_live {
            return Err(OwnerError::WrongState);
        }
        // Allocation has already transferred ownership. Record it before
        // semantic validation so rollback can return or retain every frame.
        self.ledger.push_owned(frame)?;
        self.ledger.validate_latest()
    }

    fn publish(&mut self, root: u64) -> Result<(), OwnerError> {
        if self.state != LifecycleState::Building || !self.generation_live {
            return Err(OwnerError::WrongState);
        }
        if self.ledger.frame_for(FrameRole::Root) != Some(root)
            || self.ledger.len() != TASK_FRAME_COUNT
        {
            return Err(OwnerError::RootNotOwned);
        }
        self.root = Some(root);
        self.state = LifecycleState::Inactive;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), OwnerError> {
        if self.state != LifecycleState::Inactive || !self.generation_live {
            return Err(OwnerError::WrongState);
        }
        self.state = LifecycleState::Active;
        Ok(())
    }

    pub fn recover(&mut self) -> Result<(), OwnerError> {
        if self.state != LifecycleState::Active || !self.generation_live {
            return Err(OwnerError::WrongState);
        }
        self.state = LifecycleState::Inactive;
        Ok(())
    }

    pub fn mapping_token(&self, virtual_address: u64) -> Result<MappingToken, OwnerError> {
        if !self.generation_live || self.state == LifecycleState::Dead {
            return Err(OwnerError::StaleOwner);
        }
        if !virtual_address.is_multiple_of(PAGE_SIZE)
            || !USER_MAPPINGS
                .iter()
                .any(|mapping| mapping.virtual_address == virtual_address)
        {
            return Err(OwnerError::InvalidTokenAddress);
        }
        Ok(MappingToken {
            generation: self.generation,
            virtual_address,
        })
    }

    pub fn validate_token(&self, token: MappingToken) -> Result<(), OwnerError> {
        if !self.generation_live || self.state == LifecycleState::Dead {
            return Err(OwnerError::StaleOwner);
        }
        if token.generation != self.generation {
            return Err(OwnerError::StaleToken);
        }
        if !token.virtual_address.is_multiple_of(PAGE_SIZE)
            || !USER_MAPPINGS
                .iter()
                .any(|mapping| mapping.virtual_address == token.virtual_address)
        {
            return Err(OwnerError::InvalidTokenAddress);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingToken {
    generation: u64,
    virtual_address: u64,
}

impl MappingToken {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }
}

pub trait AddressSpaceBackend {
    type Error;

    fn allocate_frame(&mut self, role: FrameRole) -> Result<u64, Self::Error>;
    fn prepare_frame(
        &mut self,
        generation: u64,
        role: FrameRole,
        frame: u64,
    ) -> Result<(), Self::Error>;
    fn install_link(&mut self, link: LinkSpec, parent: u64, child: u64) -> Result<(), Self::Error>;
    fn remove_link(&mut self, link: LinkSpec, parent: u64, child: u64) -> Result<(), Self::Error>;
    fn clear_shared_entries(&mut self, root: u64) -> Result<(), Self::Error>;
    fn clear_temporary_window(&mut self) -> Result<(), Self::Error>;
    fn verify_unreachable(&mut self, frames: &[OwnedFrame]) -> Result<(), Self::Error>;
    fn return_frame(&mut self, frame: OwnedFrame) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum BuildCause<E> {
    Backend(E),
    Owner(OwnerError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct BuildFailure<E> {
    pub cause: BuildCause<E>,
    pub rollback_error: Option<E>,
    pub retained: FrameLedger,
}

// The error deliberately owns the fixed ledger so rollback failure cannot
// lose frame ownership; heap boxing is unavailable in this no_std boundary.
#[allow(clippy::result_large_err)]
pub fn construct_address_space<B: AddressSpaceBackend>(
    generation: u64,
    backend: &mut B,
) -> Result<AddressSpaceOwner, BuildFailure<B::Error>> {
    let mut owner = AddressSpaceOwner::begin(generation).map_err(|error| BuildFailure {
        cause: BuildCause::Owner(error),
        rollback_error: None,
        retained: FrameLedger::new(),
    })?;
    let mut installed_links = 0;

    for role in FrameRole::ALL {
        let frame = match backend.allocate_frame(role) {
            Ok(frame) => frame,
            Err(error) => {
                return Err(rollback_build(
                    BuildCause::Backend(error),
                    &mut owner,
                    installed_links,
                    backend,
                ));
            }
        };
        if let Err(error) = owner.record_frame(OwnedFrame {
            role,
            physical_start: frame,
        }) {
            return Err(rollback_build(
                BuildCause::Owner(error),
                &mut owner,
                installed_links,
                backend,
            ));
        }
        if let Err(error) = backend.prepare_frame(generation, role, frame) {
            return Err(rollback_build(
                BuildCause::Backend(error),
                &mut owner,
                installed_links,
                backend,
            ));
        }
    }

    for link in BUILD_LINKS {
        let parent = owner.ledger.frame_for(link.parent).expect("fixed parent");
        let child = owner.ledger.frame_for(link.child).expect("fixed child");
        if let Err(error) = backend.install_link(link, parent, child) {
            return Err(rollback_build(
                BuildCause::Backend(error),
                &mut owner,
                installed_links,
                backend,
            ));
        }
        installed_links += 1;
    }

    let root = owner.ledger.frame_for(FrameRole::Root).expect("fixed root");
    if let Err(error) = owner.publish(root) {
        return Err(rollback_build(
            BuildCause::Owner(error),
            &mut owner,
            installed_links,
            backend,
        ));
    }
    Ok(owner)
}

#[derive(Debug, Eq, PartialEq)]
pub struct AddressSpacePair {
    pub first: AddressSpaceOwner,
    pub second: AddressSpaceOwner,
}

#[derive(Debug, Eq, PartialEq)]
// The failure owns every retained fixed ledger or non-cloneable owner. Heap
// indirection is unavailable at this no_std ownership boundary.
#[allow(clippy::large_enum_variant)]
pub enum PairBuildFailure<E> {
    First(BuildFailure<E>),
    Second {
        second: BuildFailure<E>,
        first_teardown: Option<CheckedTeardownFailure<E>>,
    },
}

/// Construct two inactive owners and publish neither to a caller unless both
/// constructions succeed.
///
/// If the second construction fails, its own rollback runs first and the
/// already-built first owner is then torn down through the normal checked path.
/// Any retained ownership is returned in the error instead of being forgotten.
#[allow(clippy::result_large_err)]
pub fn construct_address_space_pair<B: AddressSpaceBackend>(
    first_generation: u64,
    second_generation: u64,
    backend: &mut B,
) -> Result<AddressSpacePair, PairBuildFailure<B::Error>> {
    let first =
        construct_address_space(first_generation, backend).map_err(PairBuildFailure::First)?;
    match construct_address_space(second_generation, backend) {
        Ok(second) => Ok(AddressSpacePair { first, second }),
        Err(second) => {
            let first_teardown = teardown_checked(first, backend).err();
            Err(PairBuildFailure::Second {
                second,
                first_teardown,
            })
        }
    }
}

fn rollback_build<B: AddressSpaceBackend>(
    cause: BuildCause<B::Error>,
    owner: &mut AddressSpaceOwner,
    installed_links: usize,
    backend: &mut B,
) -> BuildFailure<B::Error> {
    let rollback_error = rollback_owned_frames(owner, installed_links, backend).err();
    BuildFailure {
        cause,
        rollback_error,
        retained: owner.ledger,
    }
}

fn rollback_owned_frames<B: AddressSpaceBackend>(
    owner: &mut AddressSpaceOwner,
    installed_links: usize,
    backend: &mut B,
) -> Result<(), B::Error> {
    for link in BUILD_LINKS[..installed_links].iter().rev().copied() {
        let parent = owner
            .ledger
            .frame_for(link.parent)
            .expect("installed parent");
        let child = owner.ledger.frame_for(link.child).expect("installed child");
        backend.remove_link(link, parent, child)?;
    }
    if let Some(root) = owner.ledger.frame_for(FrameRole::Root) {
        backend.clear_shared_entries(root)?;
    }
    backend.clear_temporary_window()?;
    backend.verify_unreachable(owner.ledger.as_slice())?;
    while let Some(frame) = owner.ledger.as_slice().last().copied() {
        backend.return_frame(frame)?;
        owner.ledger.pop();
    }
    owner.generation_live = false;
    owner.root = None;
    owner.state = LifecycleState::Dead;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub struct TeardownFailure<E> {
    pub error: E,
    pub owner: AddressSpaceOwner,
}

#[allow(clippy::result_large_err)]
fn teardown_address_space<B: AddressSpaceBackend>(
    mut owner: AddressSpaceOwner,
    backend: &mut B,
) -> Result<AddressSpaceOwner, TeardownFailure<B::Error>> {
    owner.generation_live = false;
    if let Err(error) = teardown_inactive(&mut owner, backend) {
        return Err(TeardownFailure { error, owner });
    }
    owner.root = None;
    owner.state = LifecycleState::Dead;
    Ok(owner)
}

// A failed teardown deliberately returns the non-cloneable owner by value.
#[allow(clippy::result_large_err)]
pub fn teardown_checked<B: AddressSpaceBackend>(
    owner: AddressSpaceOwner,
    backend: &mut B,
) -> Result<AddressSpaceOwner, CheckedTeardownFailure<B::Error>> {
    if owner.state != LifecycleState::Inactive || !owner.generation_live {
        return Err(CheckedTeardownFailure::Owner {
            error: OwnerError::WrongState,
            owner,
        });
    }
    teardown_address_space(owner, backend).map_err(CheckedTeardownFailure::Backend)
}

#[derive(Debug, Eq, PartialEq)]
pub enum CheckedTeardownFailure<E> {
    Owner {
        error: OwnerError,
        owner: AddressSpaceOwner,
    },
    Backend(TeardownFailure<E>),
}

fn teardown_inactive<B: AddressSpaceBackend>(
    owner: &mut AddressSpaceOwner,
    backend: &mut B,
) -> Result<(), B::Error> {
    for link in BUILD_LINKS.iter().rev().copied() {
        let parent = owner
            .ledger
            .frame_for(link.parent)
            .expect("published parent");
        let child = owner.ledger.frame_for(link.child).expect("published child");
        backend.remove_link(link, parent, child)?;
    }
    let root = owner
        .ledger
        .frame_for(FrameRole::Root)
        .expect("published root");
    backend.clear_shared_entries(root)?;
    backend.clear_temporary_window()?;
    backend.verify_unreachable(owner.ledger.as_slice())?;
    while let Some(frame) = owner.ledger.as_slice().last().copied() {
        backend.return_frame(frame)?;
        owner.ledger.pop();
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultObservation {
    pub expected_task: u64,
    pub observed_task: u64,
    pub owner_state: LifecycleState,
    pub expected_root: u64,
    pub current_root: u64,
    pub code_selector: u64,
    pub fault_address: u64,
    pub error_code: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultRejection {
    NoActiveOwner,
    WrongTask,
    WrongRoot,
    WrongPrivilege,
    WrongAddress,
    ProtectionViolation,
    NotWrite,
    NotUser,
    ReservedBit,
    InstructionFetch,
    UnexpectedCause,
}

pub fn classify_expected_user_fault(observation: FaultObservation) -> Result<(), FaultRejection> {
    if observation.owner_state != LifecycleState::Active {
        return Err(FaultRejection::NoActiveOwner);
    }
    if observation.observed_task != observation.expected_task {
        return Err(FaultRejection::WrongTask);
    }
    if observation.current_root != observation.expected_root {
        return Err(FaultRejection::WrongRoot);
    }
    if observation.code_selector & 3 != 3 {
        return Err(FaultRejection::WrongPrivilege);
    }
    if observation.fault_address != INVALID_WRITE_TARGET {
        return Err(FaultRejection::WrongAddress);
    }
    if observation.error_code & 1 != 0 {
        return Err(FaultRejection::ProtectionViolation);
    }
    if observation.error_code & (1 << 1) == 0 {
        return Err(FaultRejection::NotWrite);
    }
    if observation.error_code & (1 << 2) == 0 {
        return Err(FaultRejection::NotUser);
    }
    if observation.error_code & (1 << 3) != 0 {
        return Err(FaultRejection::ReservedBit);
    }
    if observation.error_code & (1 << 4) != 0 {
        return Err(FaultRejection::InstructionFetch);
    }
    if observation.error_code != 0x06 {
        return Err(FaultRejection::UnexpectedCause);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Injected,
        InvalidState,
        DuplicateMapping,
        MissingMapping,
        ReturnRejected,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Allocate(FrameRole, u64),
        Prepare(FrameRole, u64),
        Install(FrameRole, FrameRole),
        Remove(FrameRole, FrameRole),
        ClearShared,
        ClearWindow,
        Verify,
        Return(FrameRole, u64),
    }

    struct ModelBackend {
        fail_forward_at: Option<usize>,
        forward_step: usize,
        reject_return_at: Option<usize>,
        returned: usize,
        next_frame: u64,
        frame_sequence: Vec<u64>,
        frame_sequence_index: usize,
        live: Vec<OwnedFrame>,
        links: Vec<(LinkSpec, u64, u64)>,
        events: Vec<Event>,
        shared_roots: Vec<u64>,
        window_clear: bool,
    }

    impl ModelBackend {
        fn new() -> Self {
            Self {
                fail_forward_at: None,
                forward_step: 0,
                reject_return_at: None,
                returned: 0,
                next_frame: 0x1000,
                frame_sequence: Vec::new(),
                frame_sequence_index: 0,
                live: Vec::new(),
                links: Vec::new(),
                events: Vec::new(),
                shared_roots: Vec::new(),
                window_clear: true,
            }
        }

        fn failing(step: usize) -> Self {
            Self {
                fail_forward_at: Some(step),
                ..Self::new()
            }
        }

        fn with_frames(frames: &[u64]) -> Self {
            Self {
                frame_sequence: frames.to_vec(),
                ..Self::new()
            }
        }

        fn forward(&mut self) -> Result<(), TestError> {
            let current = self.forward_step;
            self.forward_step += 1;
            if self.fail_forward_at == Some(current) {
                Err(TestError::Injected)
            } else {
                Ok(())
            }
        }
    }

    impl AddressSpaceBackend for ModelBackend {
        type Error = TestError;

        fn allocate_frame(&mut self, role: FrameRole) -> Result<u64, Self::Error> {
            self.forward()?;
            let frame =
                if let Some(frame) = self.frame_sequence.get(self.frame_sequence_index).copied() {
                    self.frame_sequence_index += 1;
                    frame
                } else {
                    let frame = self.next_frame;
                    self.next_frame += PAGE_SIZE;
                    frame
                };
            let owned = OwnedFrame {
                role,
                physical_start: frame,
            };
            self.live.push(owned);
            self.events.push(Event::Allocate(role, frame));
            Ok(frame)
        }

        fn prepare_frame(
            &mut self,
            _generation: u64,
            role: FrameRole,
            frame: u64,
        ) -> Result<(), Self::Error> {
            self.forward()?;
            if !self.live.contains(&OwnedFrame {
                role,
                physical_start: frame,
            }) {
                return Err(TestError::InvalidState);
            }
            if role == FrameRole::Root {
                self.shared_roots.push(frame);
            }
            self.events.push(Event::Prepare(role, frame));
            Ok(())
        }

        fn install_link(
            &mut self,
            link: LinkSpec,
            parent: u64,
            child: u64,
        ) -> Result<(), Self::Error> {
            self.forward()?;
            if self.links.contains(&(link, parent, child)) {
                return Err(TestError::DuplicateMapping);
            }
            self.links.push((link, parent, child));
            self.events.push(Event::Install(link.parent, link.child));
            Ok(())
        }

        fn remove_link(
            &mut self,
            link: LinkSpec,
            parent: u64,
            child: u64,
        ) -> Result<(), Self::Error> {
            let Some(position) = self
                .links
                .iter()
                .rposition(|installed| *installed == (link, parent, child))
            else {
                return Err(TestError::MissingMapping);
            };
            self.links.remove(position);
            self.events.push(Event::Remove(link.parent, link.child));
            Ok(())
        }

        fn clear_shared_entries(&mut self, root: u64) -> Result<(), Self::Error> {
            if let Some(position) = self
                .shared_roots
                .iter()
                .position(|candidate| *candidate == root)
            {
                self.shared_roots.remove(position);
            }
            self.events.push(Event::ClearShared);
            Ok(())
        }

        fn clear_temporary_window(&mut self) -> Result<(), Self::Error> {
            self.window_clear = true;
            self.events.push(Event::ClearWindow);
            Ok(())
        }

        fn verify_unreachable(&mut self, frames: &[OwnedFrame]) -> Result<(), Self::Error> {
            let owns = |address: u64| frames.iter().any(|frame| frame.physical_start == address);
            if self
                .links
                .iter()
                .any(|(_, parent, child)| owns(*parent) || owns(*child))
                || self.shared_roots.iter().any(|root| owns(*root))
                || !self.window_clear
            {
                return Err(TestError::InvalidState);
            }
            self.events.push(Event::Verify);
            Ok(())
        }

        fn return_frame(&mut self, frame: OwnedFrame) -> Result<(), Self::Error> {
            if self.reject_return_at == Some(self.returned) {
                return Err(TestError::ReturnRejected);
            }
            self.returned += 1;
            let Some(position) = self.live.iter().position(|candidate| *candidate == frame) else {
                return Err(TestError::InvalidState);
            };
            self.live.remove(position);
            self.events
                .push(Event::Return(frame.role, frame.physical_start));
            Ok(())
        }
    }

    #[test]
    fn fixed_layout_is_canonical_aligned_disjoint_and_wx_safe() {
        assert_eq!(Ok(()), validate_fixed_layout());
        assert_eq!(USER_PML4_INDEX, pml4_index(USER_TEXT));
        assert_eq!(USER_PML4_INDEX, pml4_index(USER_STACK));
        assert!(!USER_TEXT_FLAGS.contains(MappingFlags::WRITABLE));
        assert!(!USER_TEXT_FLAGS.contains(MappingFlags::NO_EXECUTE));
        assert!(USER_STACK_FLAGS.contains(MappingFlags::WRITABLE));
        assert!(USER_STACK_FLAGS.contains(MappingFlags::NO_EXECUTE));
        assert!(!SUPERVISOR_RX_FLAGS.contains(MappingFlags::USER_ACCESSIBLE));
        assert!(!SUPERVISOR_RW_FLAGS.contains(MappingFlags::USER_ACCESSIBLE));
    }

    #[test]
    fn bootstrap_budget_fails_closed_at_exact_bound() {
        let mut budget = BootstrapBudget::new();
        for expected in 0..BOOTSTRAP_PAGE_TABLE_FRAMES {
            assert_eq!(Ok(expected), budget.claim());
        }
        assert_eq!(BOOTSTRAP_PAGE_TABLE_FRAMES, budget.used());
        assert_eq!(Err(BootstrapBudgetError::Exhausted), budget.claim());
        assert_eq!(BOOTSTRAP_PAGE_TABLE_FRAMES, budget.used());
    }

    #[test]
    fn construction_and_teardown_follow_reverse_ownership_order() {
        let mut backend = ModelBackend::new();
        let mut owner = construct_address_space(7, &mut backend).unwrap();
        assert_eq!(LifecycleState::Inactive, owner.state());
        assert_eq!(Some(0x1000), owner.root());
        assert_eq!(TASK_FRAME_COUNT, owner.ledger().len());
        owner.activate().unwrap();
        assert_eq!(Err(OwnerError::WrongState), owner.activate());
        owner.recover().unwrap();

        let dead = teardown_checked(owner, &mut backend).unwrap();
        assert_eq!(LifecycleState::Dead, dead.state());
        assert!(dead.ledger().is_empty());
        assert!(backend.live.is_empty());

        let returned: Vec<_> = backend
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Return(role, _) => Some(*role),
                _ => None,
            })
            .collect();
        assert_eq!(
            vec![
                FrameRole::Stack,
                FrameRole::Text,
                FrameRole::StackPml1,
                FrameRole::TextPml1,
                FrameRole::UserPml2,
                FrameRole::UserPml3,
                FrameRole::Root,
            ],
            returned
        );
        let verify = backend
            .events
            .iter()
            .position(|event| *event == Event::Verify)
            .unwrap();
        let first_return = backend
            .events
            .iter()
            .position(|event| matches!(event, Event::Return(_, _)))
            .unwrap();
        assert!(verify < first_return);
        let teardown_start = backend
            .events
            .iter()
            .rposition(|event| matches!(event, Event::Install(_, _)))
            .unwrap()
            + 1;
        let teardown = &backend.events[teardown_start..];
        let mut expected = BUILD_LINKS
            .iter()
            .rev()
            .map(|link| Event::Remove(link.parent, link.child))
            .collect::<Vec<_>>();
        expected.extend([Event::ClearShared, Event::ClearWindow, Event::Verify]);
        expected.extend(
            FrameRole::ALL
                .iter()
                .rev()
                .enumerate()
                .map(|(index, role)| {
                    Event::Return(
                        *role,
                        0x1000 + (TASK_FRAME_COUNT - 1 - index) as u64 * PAGE_SIZE,
                    )
                }),
        );
        assert_eq!(expected, teardown);
    }

    #[test]
    fn fragmented_frames_are_returned_by_ownership_order_not_address() {
        let frames = [
            0, 0x23_000, 0xe5_000, 0x47_000, 0xb9_000, 0x6b_000, 0xfd_000,
        ];
        let mut backend = ModelBackend::with_frames(&frames);
        let owner = construct_address_space(8, &mut backend).unwrap();
        assert_eq!(Some(0), owner.root());
        let dead = teardown_checked(owner, &mut backend).unwrap();

        assert_eq!(LifecycleState::Dead, dead.state());
        let returned: Vec<_> = backend
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Return(_, frame) => Some(*frame),
                _ => None,
            })
            .collect();
        assert_eq!(frames.into_iter().rev().collect::<Vec<_>>(), returned);
    }

    #[test]
    fn rejected_allocations_remain_owned_until_rollback_returns_them() {
        let mut unaligned = ModelBackend::with_frames(&[1]);
        let failure = construct_address_space(18, &mut unaligned).unwrap_err();
        assert_eq!(BuildCause::Owner(OwnerError::InvalidFrame), failure.cause);
        assert_eq!(None, failure.rollback_error);
        assert!(failure.retained.is_empty());
        assert!(unaligned.live.is_empty());
        assert_eq!(
            Some(&Event::Return(FrameRole::Root, 1)),
            unaligned.events.last()
        );

        let mut duplicate = ModelBackend::with_frames(&[0x1000, 0x1000]);
        let failure = construct_address_space(19, &mut duplicate).unwrap_err();
        assert_eq!(BuildCause::Owner(OwnerError::DuplicateFrame), failure.cause);
        assert_eq!(None, failure.rollback_error);
        assert!(failure.retained.is_empty());
        assert!(duplicate.live.is_empty());
        assert_eq!(
            vec![
                Event::Return(FrameRole::UserPml3, 0x1000),
                Event::Return(FrameRole::Root, 0x1000),
            ],
            duplicate
                .events
                .iter()
                .filter(|event| matches!(event, Event::Return(_, _)))
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_forward_failure_rolls_back_without_publishing() {
        let forward_steps = TASK_FRAME_COUNT * 2 + BUILD_LINKS.len();
        for fail_at in 0..forward_steps {
            let mut backend = ModelBackend::failing(fail_at);
            let failure = construct_address_space(9, &mut backend).unwrap_err();
            assert_eq!(
                Some(TestError::Injected),
                match failure.cause {
                    BuildCause::Backend(error) => Some(error),
                    BuildCause::Owner(_) => None,
                }
            );
            assert_eq!(None, failure.rollback_error);
            assert!(failure.retained.is_empty());
            assert!(backend.live.is_empty(), "failure step {fail_at}");
            assert!(backend.links.is_empty(), "failure step {fail_at}");
        }
    }

    #[test]
    fn every_second_construction_failure_unwinds_the_first_owner() {
        let forward_steps = TASK_FRAME_COUNT * 2 + BUILD_LINKS.len();
        for second_step in 0..forward_steps {
            let mut backend = ModelBackend::failing(forward_steps + second_step);
            let failure = construct_address_space_pair(21, 22, &mut backend).unwrap_err();
            let PairBuildFailure::Second {
                second,
                first_teardown,
            } = failure
            else {
                panic!("expected second-owner failure")
            };
            assert_eq!(
                Some(TestError::Injected),
                match second.cause {
                    BuildCause::Backend(error) => Some(error),
                    BuildCause::Owner(_) => None,
                }
            );
            assert_eq!(None, second.rollback_error);
            assert!(second.retained.is_empty());
            assert!(first_teardown.is_none());
            assert!(backend.live.is_empty(), "second step {second_step}");
            assert!(backend.links.is_empty(), "second step {second_step}");
            assert!(backend.shared_roots.is_empty(), "second step {second_step}");
        }
    }

    #[test]
    fn successful_pair_can_teardown_first_owner_while_second_remains() {
        let mut backend = ModelBackend::new();
        let pair = construct_address_space_pair(31, 32, &mut backend).unwrap();
        assert_eq!(TASK_FRAME_COUNT * 2, backend.live.len());

        let first_dead = teardown_checked(pair.first, &mut backend).unwrap();
        assert_eq!(LifecycleState::Dead, first_dead.state());
        assert_eq!(TASK_FRAME_COUNT, backend.live.len());
        assert_eq!(BUILD_LINKS.len(), backend.links.len());

        let second_dead = teardown_checked(pair.second, &mut backend).unwrap();
        assert_eq!(LifecycleState::Dead, second_dead.state());
        assert!(backend.live.is_empty());
        assert!(backend.links.is_empty());
        assert!(backend.shared_roots.is_empty());
    }

    #[test]
    fn rejected_frame_return_preserves_remaining_ownership() {
        let mut backend = ModelBackend::new();
        let owner = construct_address_space(11, &mut backend).unwrap();
        backend.reject_return_at = Some(2);
        let failure = teardown_checked(owner, &mut backend).unwrap_err();
        let CheckedTeardownFailure::Backend(failure) = failure else {
            panic!("expected backend failure")
        };
        assert_eq!(TestError::ReturnRejected, failure.error);
        assert_eq!(TASK_FRAME_COUNT - 2, failure.owner.ledger().len());
        assert_eq!(TASK_FRAME_COUNT - 2, backend.live.len());
        assert_eq!(
            Err(OwnerError::StaleOwner),
            failure.owner.mapping_token(USER_TEXT)
        );
    }

    #[test]
    fn lifecycle_rejections_preserve_state_and_tokens_are_generation_bound() {
        let mut backend = ModelBackend::new();
        let mut owner = construct_address_space(13, &mut backend).unwrap();
        let token = owner.mapping_token(USER_TEXT).unwrap();
        assert_eq!(13, token.generation());
        assert_eq!(Ok(()), owner.validate_token(token));
        assert_eq!(Err(OwnerError::WrongState), owner.recover());
        assert_eq!(LifecycleState::Inactive, owner.state());
        assert_eq!(
            Err(OwnerError::InvalidTokenAddress),
            owner.mapping_token(INVALID_WRITE_TARGET)
        );
        let stale = MappingToken {
            generation: 12,
            virtual_address: USER_TEXT,
        };
        assert_eq!(Err(OwnerError::StaleToken), owner.validate_token(stale));
        owner.activate().unwrap();
        let failure = teardown_checked(owner, &mut backend).unwrap_err();
        let CheckedTeardownFailure::Owner { error, owner } = failure else {
            panic!("expected lifecycle rejection")
        };
        assert_eq!(OwnerError::WrongState, error);
        assert_eq!(LifecycleState::Active, owner.state());
        assert_eq!(TASK_FRAME_COUNT, owner.ledger().len());
    }

    #[test]
    fn dead_owner_and_mapping_token_remain_stale() {
        let mut backend = ModelBackend::new();
        let owner = construct_address_space(14, &mut backend).unwrap();
        let token = owner.mapping_token(USER_TEXT).unwrap();
        let dead = teardown_checked(owner, &mut backend).unwrap();

        assert_eq!(Err(OwnerError::StaleOwner), dead.mapping_token(USER_TEXT));
        assert_eq!(Err(OwnerError::StaleOwner), dead.validate_token(token));
        let failure = teardown_checked(dead, &mut backend).unwrap_err();
        let CheckedTeardownFailure::Owner { error, owner } = failure else {
            panic!("expected dead-owner rejection")
        };
        assert_eq!(OwnerError::WrongState, error);
        assert_eq!(LifecycleState::Dead, owner.state());
        assert!(owner.ledger().is_empty());
    }

    #[test]
    fn duplicate_install_and_absent_remove_are_distinct_and_state_preserving() {
        let link = BUILD_LINKS[0];
        let mut duplicate = ModelBackend::new();
        duplicate.links.push((link, 0x1000, 0x2000));
        let before = duplicate.links.clone();
        assert_eq!(
            Err(TestError::DuplicateMapping),
            duplicate.install_link(link, 0x1000, 0x2000)
        );
        assert_eq!(before, duplicate.links);

        let mut absent = ModelBackend::new();
        assert_eq!(
            Err(TestError::MissingMapping),
            absent.remove_link(link, 0x1000, 0x2000)
        );
        assert!(absent.links.is_empty());
    }

    fn expected_observation() -> FaultObservation {
        FaultObservation {
            expected_task: 1,
            observed_task: 1,
            owner_state: LifecycleState::Active,
            expected_root: 0x2000,
            current_root: 0x2000,
            code_selector: 0x23,
            fault_address: INVALID_WRITE_TARGET,
            error_code: 0x06,
        }
    }

    #[test]
    fn expected_user_write_fault_is_exact() {
        assert_eq!(Ok(()), classify_expected_user_fault(expected_observation()));

        let cases = [
            (
                FaultObservation {
                    owner_state: LifecycleState::Inactive,
                    ..expected_observation()
                },
                FaultRejection::NoActiveOwner,
            ),
            (
                FaultObservation {
                    observed_task: 2,
                    ..expected_observation()
                },
                FaultRejection::WrongTask,
            ),
            (
                FaultObservation {
                    current_root: 0x3000,
                    ..expected_observation()
                },
                FaultRejection::WrongRoot,
            ),
            (
                FaultObservation {
                    code_selector: 0x08,
                    ..expected_observation()
                },
                FaultRejection::WrongPrivilege,
            ),
            (
                FaultObservation {
                    fault_address: USER_TEXT,
                    ..expected_observation()
                },
                FaultRejection::WrongAddress,
            ),
            (
                FaultObservation {
                    error_code: 0x07,
                    ..expected_observation()
                },
                FaultRejection::ProtectionViolation,
            ),
            (
                FaultObservation {
                    error_code: 0x04,
                    ..expected_observation()
                },
                FaultRejection::NotWrite,
            ),
            (
                FaultObservation {
                    error_code: 0x02,
                    ..expected_observation()
                },
                FaultRejection::NotUser,
            ),
            (
                FaultObservation {
                    error_code: 0x0e,
                    ..expected_observation()
                },
                FaultRejection::ReservedBit,
            ),
            (
                FaultObservation {
                    error_code: 0x16,
                    ..expected_observation()
                },
                FaultRejection::InstructionFetch,
            ),
            (
                FaultObservation {
                    error_code: 0x26,
                    ..expected_observation()
                },
                FaultRejection::UnexpectedCause,
            ),
        ];
        for (observation, rejection) in cases {
            assert_eq!(Err(rejection), classify_expected_user_fault(observation));
        }
    }

    #[test]
    fn fixed_metadata_bounds_match_adr() {
        assert_eq!(32, BOOTSTRAP_PAGE_TABLE_FRAMES);
        assert_eq!(16, TASK_LEDGER_CAPACITY);
        assert_eq!(7, TASK_FRAME_COUNT);
        assert!(core::mem::size_of::<AddressSpaceOwner>() <= 320);
    }
}
