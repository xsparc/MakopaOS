#![no_std]

//! Fixed, host-testable state for the first MakopaOS task, IPC, and capability
//! boundary.
//!
//! The crate deliberately contains no allocator, architecture access, or
//! third-party dependency. Architecture code owns address spaces and performs
//! the one-way trap and resume transfers; this crate owns their deterministic
//! two-task scheduling, inline-message state, and task-local authority tables.

use core::mem::{offset_of, size_of};

pub const TASK_COUNT: usize = 2;
pub const SENDER_TASK_ID: u64 = 1;
pub const RECEIVER_TASK_ID: u64 = 2;
pub const ENDPOINT_ID: u64 = 1;
pub const ENDPOINT_GENERATION: u64 = 1;
pub const CAPABILITY_SLOT_COUNT: usize = 16;
pub const CAPABILITY_SLOT_BITS: u32 = 4;
pub const CAPABILITY_GENERATION_MAX: u64 = (1_u64 << 60) - 1;
pub const CAPABILITY_RIGHT_SEND: u64 = 1 << 0;
pub const CAPABILITY_RIGHT_RECEIVE: u64 = 1 << 1;
pub const CAPABILITY_RIGHT_DUPLICATE: u64 = 1 << 2;
pub const CAPABILITY_RIGHT_START: u64 = 1 << 3;
pub const CAPABILITY_RIGHT_SUBMIT_APPROVAL: u64 = 1 << 4;
pub const CAPABILITY_RIGHT_DECIDE_APPROVAL: u64 = 1 << 5;
pub const CAPABILITY_RIGHT_COMMIT_EFFECT: u64 = 1 << 6;
pub const CAPABILITY_RIGHTS_V1: u64 = CAPABILITY_RIGHT_SEND
    | CAPABILITY_RIGHT_RECEIVE
    | CAPABILITY_RIGHT_DUPLICATE
    | CAPABILITY_RIGHT_START
    | CAPABILITY_RIGHT_SUBMIT_APPROVAL
    | CAPABILITY_RIGHT_DECIDE_APPROVAL
    | CAPABILITY_RIGHT_COMMIT_EFFECT;
pub const INITIAL_CAPABILITY_HANDLE: u64 = 1 << CAPABILITY_SLOT_BITS;
pub const SUPERVISOR_TASK_CONTROL_HANDLE: u64 = INITIAL_CAPABILITY_HANDLE;
pub const SUPERVISOR_DECISION_HANDLE: u64 = INITIAL_CAPABILITY_HANDLE + 1;
pub const SUPERVISOR_EFFECT_HANDLE: u64 = INITIAL_CAPABILITY_HANDLE + 2;
pub const WORKLOAD_APPROVAL_HANDLE: u64 = INITIAL_CAPABILITY_HANDLE;
pub const SUPERVISOR_GENERATION: u64 = 4;
pub const WORKLOAD_GENERATION: u64 = 5;
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_BYTE_SIZE: u32 = 184;
pub const MANIFEST_ROUTE_COUNT_MAX: usize = 4;
pub const MANIFEST_ID: u64 = 1;
pub const PRINCIPAL_ID: u64 = 1;
pub const WORKLOAD_IMAGE_ID: u64 = 1;
pub const TASK_CONTROL_OBJECT_ID: u64 = 1;
pub const APPROVAL_BROKER_OBJECT_ID: u64 = 1;
pub const TEST_EFFECT_OBJECT_ID: u64 = 1;
pub const FIXED_OBJECT_GENERATION: u64 = 1;
pub const APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE: u64 = 1;
pub const APPROVAL_ACTION_ID_COMMIT_SYNTHETIC_VALUE: u64 = 1;
pub const DECISION_DENY: u64 = 0;
pub const DECISION_APPROVE: u64 = 1;
pub const DECISION_EXPIRE: u64 = 2;
pub const DPL3_INTERRUPT_GATE_ATTRIBUTES: u8 = 0xee;
pub const CR4_FSGSBASE: u64 = 1 << 16;

pub const fn version_one_cr4_allowed(cr4: u64) -> bool {
    cr4 & CR4_FSGSBASE == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TaskState {
    Staged,
    Ready,
    Running,
    BlockedReceive,
    BlockedApproval,
    Exited,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerPhase {
    Inactive,
    Active,
    Teardown,
    Absent,
}

impl TaskState {
    pub const fn owner_phase(self) -> OwnerPhase {
        match self {
            Self::Staged | Self::Ready | Self::BlockedReceive | Self::BlockedApproval => {
                OwnerPhase::Inactive
            }
            Self::Running => OwnerPhase::Active,
            Self::Exited => OwnerPhase::Teardown,
            Self::Dead => OwnerPhase::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum TrapOperation {
    Yield = 0,
    Send = 1,
    Receive = 2,
    Exit = 3,
    Duplicate = 4,
    Close = 5,
    StartWorkload = 6,
    SubmitApproval = 7,
    InspectApproval = 8,
    DecideApproval = 9,
    CommitEffect = 10,
}

impl TrapOperation {
    const fn parse(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Yield),
            1 => Some(Self::Send),
            2 => Some(Self::Receive),
            3 => Some(Self::Exit),
            4 => Some(Self::Duplicate),
            5 => Some(Self::Close),
            6 => Some(Self::StartWorkload),
            7 => Some(Self::SubmitApproval),
            8 => Some(Self::InspectApproval),
            9 => Some(Self::DecideApproval),
            10 => Some(Self::CommitEffect),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum TrapStatus {
    Ok = 0,
    InvalidOperation = 1,
    InvalidEndpoint = 2,
    WrongRole = 3,
    SlotFull = 4,
    PeerExited = 5,
    InvalidHandle = 6,
    WrongObject = 7,
    RightsDenied = 8,
    InvalidRights = 9,
    HandleTableFull = 10,
    GenerationExhausted = 11,
    InvalidManifest = 12,
    InvalidRequest = 13,
    BrokerFull = 14,
    ApprovalMismatch = 15,
    ApprovalDenied = 16,
    ApprovalExpired = 17,
    EffectUnavailable = 18,
    BrokerUnavailable = 19,
    AlreadyLaunched = 20,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LaunchRouteV1 {
    pub object_type: u32,
    pub reserved: u32,
    pub object_id: u64,
    pub object_generation: u64,
    pub rights: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchManifestV1 {
    pub schema_version: u32,
    pub byte_size: u32,
    pub manifest_id: u64,
    pub principal_id: u64,
    pub target_task_id: u64,
    pub target_generation: u64,
    pub image_id: u64,
    pub route_count: u32,
    pub reserved: u32,
    pub routes: [LaunchRouteV1; MANIFEST_ROUTE_COUNT_MAX],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApprovalRequestV1 {
    pub principal_id: u64,
    pub workload_task_id: u64,
    pub workload_generation: u64,
    pub sequence: u64,
    pub action_id: u64,
    pub effect_object_id: u64,
    pub effect_object_generation: u64,
    pub argument: u64,
    pub requested_rights: u64,
    pub resulting_rights: u64,
}

pub const OBJECT_TYPE_ENDPOINT: u32 = 1;
pub const OBJECT_TYPE_TASK_CONTROL: u32 = 2;
pub const OBJECT_TYPE_APPROVAL_BROKER: u32 = 3;
pub const OBJECT_TYPE_TEST_EFFECT: u32 = 4;

pub const REGISTERED_LAUNCH_MANIFEST: LaunchManifestV1 = LaunchManifestV1 {
    schema_version: MANIFEST_SCHEMA_VERSION,
    byte_size: MANIFEST_BYTE_SIZE,
    manifest_id: MANIFEST_ID,
    principal_id: PRINCIPAL_ID,
    target_task_id: RECEIVER_TASK_ID,
    target_generation: WORKLOAD_GENERATION,
    image_id: WORKLOAD_IMAGE_ID,
    route_count: 1,
    reserved: 0,
    routes: [
        LaunchRouteV1 {
            object_type: OBJECT_TYPE_APPROVAL_BROKER,
            reserved: 0,
            object_id: APPROVAL_BROKER_OBJECT_ID,
            object_generation: FIXED_OBJECT_GENERATION,
            rights: CAPABILITY_RIGHT_SUBMIT_APPROVAL,
        },
        LaunchRouteV1 {
            object_type: 0,
            reserved: 0,
            object_id: 0,
            object_generation: 0,
            rights: 0,
        },
        LaunchRouteV1 {
            object_type: 0,
            reserved: 0,
            object_id: 0,
            object_generation: 0,
            rights: 0,
        },
        LaunchRouteV1 {
            object_type: 0,
            reserved: 0,
            object_id: 0,
            object_generation: 0,
            rights: 0,
        },
    ],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    InvalidHeader,
    InvalidIdentity,
    InvalidTarget,
    ExcessRoutes,
    MissingRoute,
    InvalidRoute,
    DuplicateRoute,
    InsufficientCapacity,
    NonzeroUnusedRoute,
}

impl LaunchManifestV1 {
    pub fn validate(
        &self,
        workload_generation: u64,
        broker_generation: u64,
        available_slots: usize,
    ) -> Result<(), ManifestError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || self.byte_size != MANIFEST_BYTE_SIZE
            || self.reserved != 0
        {
            return Err(ManifestError::InvalidHeader);
        }
        if self.manifest_id != MANIFEST_ID
            || self.principal_id != PRINCIPAL_ID
            || self.image_id != WORKLOAD_IMAGE_ID
            || self.manifest_id == 0
            || self.principal_id == 0
            || self.image_id == 0
        {
            return Err(ManifestError::InvalidIdentity);
        }
        if self.target_task_id != RECEIVER_TASK_ID
            || self.target_generation != workload_generation
            || workload_generation != WORKLOAD_GENERATION
        {
            return Err(ManifestError::InvalidTarget);
        }
        let route_count = self.route_count as usize;
        if route_count > MANIFEST_ROUTE_COUNT_MAX {
            return Err(ManifestError::ExcessRoutes);
        }
        if route_count == 0 {
            return Err(ManifestError::MissingRoute);
        }
        if available_slots < route_count {
            return Err(ManifestError::InsufficientCapacity);
        }
        for index in 0..route_count {
            let route = self.routes[index];
            if route.reserved != 0
                || route.object_type != OBJECT_TYPE_APPROVAL_BROKER
                || route.object_id != APPROVAL_BROKER_OBJECT_ID
                || route.object_generation != broker_generation
                || broker_generation != FIXED_OBJECT_GENERATION
                || route.rights != CAPABILITY_RIGHT_SUBMIT_APPROVAL
            {
                return Err(ManifestError::InvalidRoute);
            }
            if self.routes[..index].iter().any(|earlier| {
                earlier.object_type == route.object_type
                    && earlier.object_id == route.object_id
                    && earlier.object_generation == route.object_generation
            }) {
                return Err(ManifestError::DuplicateRoute);
            }
        }
        if self.routes[route_count..]
            .iter()
            .any(|route| *route != LaunchRouteV1::default())
        {
            return Err(ManifestError::NonzeroUnusedRoute);
        }
        Ok(())
    }
}

pub const MANIFEST_ROUTES_OFFSET: usize = offset_of!(LaunchManifestV1, routes);
pub const APPROVAL_SEQUENCE_OFFSET: usize = offset_of!(ApprovalRequestV1, sequence);
pub const APPROVAL_ARGUMENT_OFFSET: usize = offset_of!(ApprovalRequestV1, argument);

const _: () = assert!(size_of::<LaunchRouteV1>() == 32);
const _: () = assert!(size_of::<LaunchManifestV1>() == MANIFEST_BYTE_SIZE as usize);
const _: () = assert!(MANIFEST_ROUTES_OFFSET == 56);
const _: () = assert!(size_of::<ApprovalRequestV1>() == 80);
const _: () = assert!(APPROVAL_SEQUENCE_OFFSET == 24);
const _: () = assert!(APPROVAL_ARGUMENT_OFFSET == 56);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrapFrameV1 {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskContextV1 {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub root: u64,
    pub task_id: u64,
    pub generation: u64,
}

impl TaskContextV1 {
    pub const fn initial(
        task_id: u64,
        generation: u64,
        root: u64,
        rip: u64,
        rsp: u64,
        cs: u64,
        ss: u64,
    ) -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            rsp,
            rflags: 0x2,
            cs,
            ss,
            root,
            task_id,
            generation,
        }
    }

    pub const fn from_trap(frame: TrapFrameV1, task_id: u64, generation: u64, root: u64) -> Self {
        Self {
            rax: frame.rax,
            rbx: frame.rbx,
            rcx: frame.rcx,
            rdx: frame.rdx,
            rbp: frame.rbp,
            rsi: frame.rsi,
            rdi: frame.rdi,
            r8: frame.r8,
            r9: frame.r9,
            r10: frame.r10,
            r11: frame.r11,
            r12: frame.r12,
            r13: frame.r13,
            r14: frame.r14,
            r15: frame.r15,
            rip: frame.rip,
            rsp: frame.rsp,
            rflags: frame.rflags,
            cs: frame.cs,
            ss: frame.ss,
            root,
            task_id,
            generation,
        }
    }

    pub const fn gprs(self) -> [u64; 15] {
        [
            self.rax, self.rbx, self.rcx, self.rdx, self.rbp, self.rsi, self.rdi, self.r8, self.r9,
            self.r10, self.r11, self.r12, self.r13, self.r14, self.r15,
        ]
    }

    pub fn validate(
        &self,
        expected_task: u64,
        expected_generation: u64,
        expected_root: u64,
        policy: ContextPolicy,
    ) -> Result<(), ContextError> {
        if self.task_id != expected_task {
            return Err(ContextError::WrongTask);
        }
        if self.generation == 0 || self.generation != expected_generation {
            return Err(ContextError::WrongGeneration);
        }
        if self.root == 0 || self.root != expected_root || !self.root.is_multiple_of(4096) {
            return Err(ContextError::WrongRoot);
        }
        if !is_canonical_48(self.rip) || self.rip < policy.text_start || self.rip >= policy.text_end
        {
            return Err(ContextError::InvalidInstructionPointer);
        }
        if !is_canonical_48(self.rsp)
            || self.rsp < policy.stack_start
            || self.rsp > policy.stack_end
        {
            return Err(ContextError::InvalidStackPointer);
        }
        if self.cs != policy.user_code || self.ss != policy.user_data {
            return Err(ContextError::InvalidSelectors);
        }
        const FORBIDDEN_RFLAGS: u64 = (1 << 9) | (1 << 10) | (3 << 12);
        if self.rflags & 0x2 == 0 || self.rflags & FORBIDDEN_RFLAGS != 0 {
            return Err(ContextError::InvalidFlags);
        }
        Ok(())
    }

    fn set_result(&mut self, status: TrapStatus, value: u64) {
        self.rax = status as u64;
        self.rdx = value;
    }

    fn clear_dead(&mut self) {
        *self = Self::initial(0, 0, 0, 0, 0, 0, 0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextPolicy {
    pub text_start: u64,
    pub text_end: u64,
    pub stack_start: u64,
    pub stack_end: u64,
    pub user_code: u64,
    pub user_data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextError {
    WrongTask,
    WrongGeneration,
    WrongRoot,
    InvalidInstructionPointer,
    InvalidStackPointer,
    InvalidSelectors,
    InvalidFlags,
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

pub const CONTEXT_RAX_OFFSET: usize = offset_of!(TaskContextV1, rax);
pub const CONTEXT_RBX_OFFSET: usize = offset_of!(TaskContextV1, rbx);
pub const CONTEXT_RCX_OFFSET: usize = offset_of!(TaskContextV1, rcx);
pub const CONTEXT_RDX_OFFSET: usize = offset_of!(TaskContextV1, rdx);
pub const CONTEXT_RBP_OFFSET: usize = offset_of!(TaskContextV1, rbp);
pub const CONTEXT_RSI_OFFSET: usize = offset_of!(TaskContextV1, rsi);
pub const CONTEXT_RDI_OFFSET: usize = offset_of!(TaskContextV1, rdi);
pub const CONTEXT_R8_OFFSET: usize = offset_of!(TaskContextV1, r8);
pub const CONTEXT_R9_OFFSET: usize = offset_of!(TaskContextV1, r9);
pub const CONTEXT_R10_OFFSET: usize = offset_of!(TaskContextV1, r10);
pub const CONTEXT_R11_OFFSET: usize = offset_of!(TaskContextV1, r11);
pub const CONTEXT_R12_OFFSET: usize = offset_of!(TaskContextV1, r12);
pub const CONTEXT_R13_OFFSET: usize = offset_of!(TaskContextV1, r13);
pub const CONTEXT_R14_OFFSET: usize = offset_of!(TaskContextV1, r14);
pub const CONTEXT_R15_OFFSET: usize = offset_of!(TaskContextV1, r15);
pub const CONTEXT_RIP_OFFSET: usize = offset_of!(TaskContextV1, rip);
pub const CONTEXT_RSP_OFFSET: usize = offset_of!(TaskContextV1, rsp);
pub const CONTEXT_RFLAGS_OFFSET: usize = offset_of!(TaskContextV1, rflags);
pub const CONTEXT_CS_OFFSET: usize = offset_of!(TaskContextV1, cs);
pub const CONTEXT_SS_OFFSET: usize = offset_of!(TaskContextV1, ss);
pub const CONTEXT_ROOT_OFFSET: usize = offset_of!(TaskContextV1, root);

const _: () = assert!(size_of::<TrapFrameV1>() == 20 * 8);
const _: () = assert!(size_of::<TaskContextV1>() == 23 * 8);
const _: () = assert!(CONTEXT_RAX_OFFSET == 0);
const _: () = assert!(CONTEXT_R15_OFFSET == 14 * 8);
const _: () = assert!(CONTEXT_RIP_OFFSET == 15 * 8);
const _: () = assert!(CONTEXT_ROOT_OFFSET == 20 * 8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CapabilityHandleV1(u64);

impl CapabilityHandleV1 {
    pub const fn from_parts(slot: usize, generation: u64) -> Option<Self> {
        if slot >= CAPABILITY_SLOT_COUNT
            || generation == 0
            || generation > CAPABILITY_GENERATION_MAX
        {
            None
        } else {
            Some(Self((generation << CAPABILITY_SLOT_BITS) | slot as u64))
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    const fn decode(raw: u64) -> Option<(usize, u64)> {
        let generation = raw >> CAPABILITY_SLOT_BITS;
        if generation == 0 {
            None
        } else {
            Some(((raw & 0xf) as usize, generation))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CapabilityTableState {
    Building,
    Live,
    Closing,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityTableSnapshot {
    pub task_id: u64,
    pub task_generation: u64,
    pub state: CapabilityTableState,
    pub live_slots: usize,
    pub retired_slots: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectReference {
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilityEntry {
    task_id: u64,
    task_generation: u64,
    object_type: u32,
    rights: u64,
    object: ObjectReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilitySlot {
    generation: u64,
    retired: bool,
    entry: Option<CapabilityEntry>,
}

impl CapabilitySlot {
    const EMPTY: Self = Self {
        generation: 1,
        retired: false,
        entry: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilityTable {
    task_id: u64,
    task_generation: u64,
    state: CapabilityTableState,
    slots: [CapabilitySlot; CAPABILITY_SLOT_COUNT],
}

impl CapabilityTable {
    const fn building(task_id: u64, task_generation: u64) -> Self {
        Self {
            task_id,
            task_generation,
            state: CapabilityTableState::Building,
            slots: [CapabilitySlot::EMPTY; CAPABILITY_SLOT_COUNT],
        }
    }

    const fn dead() -> Self {
        Self {
            task_id: 0,
            task_generation: 0,
            state: CapabilityTableState::Dead,
            slots: [CapabilitySlot::EMPTY; CAPABILITY_SLOT_COUNT],
        }
    }

    fn snapshot(&self) -> CapabilityTableSnapshot {
        CapabilityTableSnapshot {
            task_id: self.task_id,
            task_generation: self.task_generation,
            state: self.state,
            live_slots: self
                .slots
                .iter()
                .filter(|slot| slot.entry.is_some())
                .count(),
            retired_slots: self.slots.iter().filter(|slot| slot.retired).count(),
        }
    }

    fn available_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.entry.is_none() && !slot.retired)
            .count()
    }

    fn install_building(&mut self, rights: u64) -> Result<u64, RuntimeError> {
        self.install_object_building(
            OBJECT_TYPE_ENDPOINT,
            ObjectReference {
                id: ENDPOINT_ID,
                generation: ENDPOINT_GENERATION,
            },
            rights,
        )
    }

    fn install_object_building(
        &mut self,
        object_type: u32,
        object: ObjectReference,
        rights: u64,
    ) -> Result<u64, RuntimeError> {
        if self.state != CapabilityTableState::Building
            || !valid_rights(object_type, rights)
            || self.task_id == 0
            || self.task_generation == 0
            || object.id == 0
            || object.generation == 0
        {
            return Err(RuntimeError::CapabilityInvariant);
        }
        self.allocate(CapabilityEntry {
            task_id: self.task_id,
            task_generation: self.task_generation,
            object_type,
            rights,
            object,
        })
        .map_err(|_| RuntimeError::CapabilityInvariant)
    }

    fn publish(&mut self) -> Result<(), RuntimeError> {
        if self.state != CapabilityTableState::Building {
            return Err(RuntimeError::CapabilityInvariant);
        }
        self.state = CapabilityTableState::Live;
        Ok(())
    }

    fn rollback_install(&mut self, raw: u64) {
        if let Some((index, generation)) = CapabilityHandleV1::decode(raw) {
            let slot = &mut self.slots[index];
            if slot.generation == generation {
                slot.entry = None;
            }
        }
    }

    fn resolve(
        &self,
        task_id: u64,
        task_generation: u64,
        raw: u64,
        required_right: u64,
    ) -> Result<CapabilityEntry, TrapStatus> {
        self.resolve_typed(
            task_id,
            task_generation,
            raw,
            OBJECT_TYPE_ENDPOINT,
            required_right,
        )
    }

    fn resolve_typed(
        &self,
        task_id: u64,
        task_generation: u64,
        raw: u64,
        object_type: u32,
        required_right: u64,
    ) -> Result<CapabilityEntry, TrapStatus> {
        if self.state != CapabilityTableState::Live
            || self.task_id != task_id
            || self.task_generation != task_generation
        {
            return Err(TrapStatus::InvalidHandle);
        }
        let (index, generation) =
            CapabilityHandleV1::decode(raw).ok_or(TrapStatus::InvalidHandle)?;
        let slot = &self.slots[index];
        if slot.retired || slot.generation != generation {
            return Err(TrapStatus::InvalidHandle);
        }
        let entry = slot.entry.ok_or(TrapStatus::InvalidHandle)?;
        if entry.task_id != task_id || entry.task_generation != task_generation {
            return Err(TrapStatus::InvalidHandle);
        }
        if entry.object_type != object_type {
            return Err(TrapStatus::WrongObject);
        }
        if entry.rights & required_right == 0 {
            return Err(TrapStatus::RightsDenied);
        }
        Ok(entry)
    }

    fn duplicate(
        &mut self,
        task_id: u64,
        task_generation: u64,
        source: u64,
        requested_rights: u64,
    ) -> Result<u64, TrapStatus> {
        let entry = self.resolve_typed(
            task_id,
            task_generation,
            source,
            OBJECT_TYPE_ENDPOINT,
            CAPABILITY_RIGHT_DUPLICATE,
        )?;
        if !valid_rights(OBJECT_TYPE_ENDPOINT, requested_rights)
            || requested_rights & !entry.rights != 0
        {
            return Err(TrapStatus::InvalidRights);
        }
        self.allocate(CapabilityEntry {
            rights: requested_rights,
            ..entry
        })
    }

    fn allocate(&mut self, entry: CapabilityEntry) -> Result<u64, TrapStatus> {
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.entry.is_none() && !slot.retired)
        else {
            return Err(if self.slots.iter().all(|slot| slot.entry.is_some()) {
                TrapStatus::HandleTableFull
            } else {
                TrapStatus::GenerationExhausted
            });
        };
        let generation = self.slots[index].generation;
        let handle = CapabilityHandleV1::from_parts(index, generation)
            .ok_or(TrapStatus::GenerationExhausted)?;
        self.slots[index].entry = Some(entry);
        Ok(handle.raw())
    }

    fn close(&mut self, task_id: u64, task_generation: u64, raw: u64) -> Result<(), TrapStatus> {
        if self.state != CapabilityTableState::Live
            || self.task_id != task_id
            || self.task_generation != task_generation
        {
            return Err(TrapStatus::InvalidHandle);
        }
        let (index, generation) =
            CapabilityHandleV1::decode(raw).ok_or(TrapStatus::InvalidHandle)?;
        let slot = &mut self.slots[index];
        if slot.retired || slot.generation != generation || slot.entry.is_none() {
            return Err(TrapStatus::InvalidHandle);
        }
        Self::remove_entry(slot);
        Ok(())
    }

    fn begin_closing(&mut self) -> Result<(), RuntimeError> {
        self.mark_closing()?;
        self.close_all()
    }

    fn mark_closing(&mut self) -> Result<(), RuntimeError> {
        if self.state != CapabilityTableState::Live {
            return Err(RuntimeError::WrongState);
        }
        self.state = CapabilityTableState::Closing;
        Ok(())
    }

    fn close_all(&mut self) -> Result<(), RuntimeError> {
        if self.state != CapabilityTableState::Closing {
            return Err(RuntimeError::WrongState);
        }
        for slot in &mut self.slots {
            if slot.entry.is_some() {
                Self::remove_entry(slot);
            }
        }
        if self.slots.iter().any(|slot| slot.entry.is_some()) {
            return Err(RuntimeError::CapabilityInvariant);
        }
        Ok(())
    }

    fn finish_dead(&mut self) -> Result<(), RuntimeError> {
        if self.state != CapabilityTableState::Closing
            || self.slots.iter().any(|slot| slot.entry.is_some())
        {
            return Err(RuntimeError::WrongState);
        }
        *self = Self::dead();
        Ok(())
    }

    fn remove_entry(slot: &mut CapabilitySlot) {
        slot.entry = None;
        if slot.generation == CAPABILITY_GENERATION_MAX {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.state == CapabilityTableState::Dead {
            if self.task_id != 0
                || self.task_generation != 0
                || self.slots != [CapabilitySlot::EMPTY; CAPABILITY_SLOT_COUNT]
            {
                return Err(RuntimeError::CapabilityInvariant);
            }
            return Ok(());
        }
        if self.task_id == 0 || self.task_generation == 0 {
            return Err(RuntimeError::CapabilityInvariant);
        }
        if self.state == CapabilityTableState::Closing
            && self.slots.iter().any(|slot| slot.entry.is_some())
        {
            return Err(RuntimeError::CapabilityInvariant);
        }
        for slot in &self.slots {
            if slot.generation == 0 || slot.generation > CAPABILITY_GENERATION_MAX {
                return Err(RuntimeError::CapabilityInvariant);
            }
            if slot.retired && slot.entry.is_some() {
                return Err(RuntimeError::CapabilityInvariant);
            }
            if let Some(entry) = slot.entry
                && (entry.task_id != self.task_id
                    || entry.task_generation != self.task_generation
                    || entry.object_type == 0
                    || !valid_rights(entry.object_type, entry.rights)
                    || entry.object.id == 0
                    || entry.object.generation == 0)
            {
                return Err(RuntimeError::CapabilityInvariant);
            }
        }
        Ok(())
    }
}

const fn valid_rights(object_type: u32, rights: u64) -> bool {
    if rights == 0 || rights & !CAPABILITY_RIGHTS_V1 != 0 {
        return false;
    }
    match object_type {
        OBJECT_TYPE_ENDPOINT => {
            rights
                & !(CAPABILITY_RIGHT_SEND | CAPABILITY_RIGHT_RECEIVE | CAPABILITY_RIGHT_DUPLICATE)
                == 0
        }
        OBJECT_TYPE_TASK_CONTROL => rights == CAPABILITY_RIGHT_START,
        OBJECT_TYPE_APPROVAL_BROKER => {
            matches!(
                rights,
                CAPABILITY_RIGHT_SUBMIT_APPROVAL | CAPABILITY_RIGHT_DECIDE_APPROVAL
            )
        }
        OBJECT_TYPE_TEST_EFFECT => rights == CAPABILITY_RIGHT_COMMIT_EFFECT,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskSlot {
    id: u64,
    generation: u64,
    state: TaskState,
    context: TaskContextV1,
    capabilities: CapabilityTable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeProfile {
    Cooperative,
    Supervised,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApprovalBrokerState {
    Building,
    Empty,
    Pending,
    Approved,
    Closing,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestPublication {
    manifest_id: u64,
    principal_id: u64,
    target_task_id: u64,
    target_generation: u64,
    image_id: u64,
    published: bool,
}

impl ManifestPublication {
    const EMPTY: Self = Self {
        manifest_id: 0,
        principal_id: 0,
        target_task_id: 0,
        target_generation: 0,
        image_id: 0,
        published: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestPublicationSnapshot {
    pub manifest_id: u64,
    pub principal_id: u64,
    pub target_task_id: u64,
    pub target_generation: u64,
    pub image_id: u64,
    pub published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApprovalBroker {
    state: ApprovalBrokerState,
    object_generation: u64,
    supervisor_task_id: u64,
    supervisor_generation: u64,
    workload_task_id: u64,
    workload_generation: u64,
    request_kind: u64,
    request: ApprovalRequestV1,
    request_present: bool,
    next_sequence: u64,
    sequence_exhausted: bool,
    decision_epoch: u64,
    approval_epoch: u64,
    expiry_epoch: u64,
}

impl ApprovalBroker {
    const DEAD: Self = Self {
        state: ApprovalBrokerState::Dead,
        object_generation: 0,
        supervisor_task_id: 0,
        supervisor_generation: 0,
        workload_task_id: 0,
        workload_generation: 0,
        request_kind: 0,
        request: ApprovalRequestV1 {
            principal_id: 0,
            workload_task_id: 0,
            workload_generation: 0,
            sequence: 0,
            action_id: 0,
            effect_object_id: 0,
            effect_object_generation: 0,
            argument: 0,
            requested_rights: 0,
            resulting_rights: 0,
        },
        request_present: false,
        next_sequence: 0,
        sequence_exhausted: false,
        decision_epoch: 0,
        approval_epoch: 0,
        expiry_epoch: 0,
    };

    const fn building(supervisor_generation: u64, workload_generation: u64) -> Self {
        Self {
            state: ApprovalBrokerState::Building,
            object_generation: FIXED_OBJECT_GENERATION,
            supervisor_task_id: SENDER_TASK_ID,
            supervisor_generation,
            workload_task_id: RECEIVER_TASK_ID,
            workload_generation,
            request_kind: 0,
            request: Self::DEAD.request,
            request_present: false,
            next_sequence: 1,
            sequence_exhausted: false,
            decision_epoch: 1,
            approval_epoch: 0,
            expiry_epoch: 0,
        }
    }

    fn clear_request(&mut self) {
        self.request_kind = 0;
        self.request = Self::DEAD.request;
        self.request_present = false;
        self.approval_epoch = 0;
        self.expiry_epoch = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalBrokerSnapshot {
    pub state: ApprovalBrokerState,
    pub object_generation: u64,
    pub supervisor_task_id: u64,
    pub supervisor_generation: u64,
    pub workload_task_id: u64,
    pub workload_generation: u64,
    pub request_kind: u64,
    pub request: ApprovalRequestV1,
    pub request_present: bool,
    pub next_sequence: u64,
    pub sequence_exhausted: bool,
    pub decision_epoch: u64,
    pub approval_epoch: u64,
    pub expiry_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyntheticEffect {
    object_generation: u64,
    supervisor_task_id: u64,
    supervisor_generation: u64,
    occupied: bool,
    value: u64,
}

impl SyntheticEffect {
    const EMPTY: Self = Self {
        object_generation: 0,
        supervisor_task_id: 0,
        supervisor_generation: 0,
        occupied: false,
        value: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticEffectSnapshot {
    pub object_generation: u64,
    pub supervisor_task_id: u64,
    pub supervisor_generation: u64,
    pub occupied: bool,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointSnapshot {
    pub object_generation: u64,
    pub sender_task: u64,
    pub sender_generation: u64,
    pub receiver_task: u64,
    pub receiver_generation: u64,
    pub occupied: bool,
    pub payload: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunQueue {
    entries: [u64; TASK_COUNT],
    len: usize,
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            entries: [0; TASK_COUNT],
            len: 0,
        }
    }

    fn push(&mut self, task: u64) -> Result<(), RuntimeError> {
        if self.entries[..self.len].contains(&task) {
            return Err(RuntimeError::DuplicateQueueMember);
        }
        if self.len == TASK_COUNT {
            return Err(RuntimeError::QueueFull);
        }
        self.entries[self.len] = task;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        let task = self.entries[0];
        for index in 1..self.len {
            self.entries[index - 1] = self.entries[index];
        }
        self.len -= 1;
        self.entries[self.len] = 0;
        Some(task)
    }

    fn contains(self, task: u64) -> bool {
        self.entries[..self.len].contains(&task)
    }

    fn as_array(self) -> [u64; TASK_COUNT] {
        self.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Runtime {
    profile: RuntimeProfile,
    tasks: [TaskSlot; TASK_COUNT],
    queue: RunQueue,
    endpoint: EndpointSnapshot,
    manifest: ManifestPublication,
    broker: ApprovalBroker,
    effect: SyntheticEffect,
}

pub const RUNTIME_METADATA_BYTES: usize = size_of::<Runtime>();
pub const RUNTIME_METADATA_BYTES_V1: usize = 3_112;

const _: () = assert!(RUNTIME_METADATA_BYTES == RUNTIME_METADATA_BYTES_V1);
const _: () = assert!(RUNTIME_METADATA_BYTES < 64 * 1024);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapOutcome {
    Resume(u64),
    Switch(u64),
    Exit(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidTask,
    InvalidGeneration,
    DuplicateGeneration,
    WrongState,
    NoRunningTask,
    MultipleRunningTasks,
    QueueFull,
    DuplicateQueueMember,
    InvalidQueueMember,
    MissingQueueMember,
    EndpointInvariant,
    NoRunnableTask,
    CapabilityInvariant,
    ManifestInvariant,
    BrokerInvariant,
    EffectInvariant,
    PublicationFailure,
}

impl Runtime {
    pub fn new(sender: TaskContextV1, receiver: TaskContextV1) -> Result<Self, RuntimeError> {
        if sender.task_id != SENDER_TASK_ID || receiver.task_id != RECEIVER_TASK_ID {
            return Err(RuntimeError::InvalidTask);
        }
        if sender.generation == 0 || receiver.generation == 0 {
            return Err(RuntimeError::InvalidGeneration);
        }
        if sender.generation == receiver.generation {
            return Err(RuntimeError::DuplicateGeneration);
        }
        Self::construct(sender, receiver, None)
    }

    pub fn new_supervised(
        supervisor: TaskContextV1,
        workload: TaskContextV1,
    ) -> Result<Self, RuntimeError> {
        if supervisor.task_id != SENDER_TASK_ID || workload.task_id != RECEIVER_TASK_ID {
            return Err(RuntimeError::InvalidTask);
        }
        if supervisor.generation != SUPERVISOR_GENERATION
            || workload.generation != WORKLOAD_GENERATION
        {
            return Err(RuntimeError::InvalidGeneration);
        }
        Self::construct_supervised(supervisor, workload, None)
    }

    fn construct(
        sender: TaskContextV1,
        receiver: TaskContextV1,
        fail_before_step: Option<usize>,
    ) -> Result<Self, RuntimeError> {
        let mut runtime = Self::unpublished(sender, receiver);
        runtime.publish_initial(fail_before_step)?;
        Ok(runtime)
    }

    fn construct_supervised(
        supervisor: TaskContextV1,
        workload: TaskContextV1,
        fail_before_step: Option<usize>,
    ) -> Result<Self, RuntimeError> {
        let mut runtime = Self::unpublished_supervised(supervisor, workload);
        runtime.publish_supervisor(fail_before_step)?;
        Ok(runtime)
    }

    fn unpublished(sender: TaskContextV1, receiver: TaskContextV1) -> Self {
        Self {
            profile: RuntimeProfile::Cooperative,
            tasks: [
                TaskSlot {
                    id: SENDER_TASK_ID,
                    generation: sender.generation,
                    state: TaskState::Ready,
                    context: sender,
                    capabilities: CapabilityTable::building(SENDER_TASK_ID, sender.generation),
                },
                TaskSlot {
                    id: RECEIVER_TASK_ID,
                    generation: receiver.generation,
                    state: TaskState::Ready,
                    context: receiver,
                    capabilities: CapabilityTable::building(RECEIVER_TASK_ID, receiver.generation),
                },
            ],
            queue: RunQueue::new(),
            endpoint: EndpointSnapshot {
                object_generation: 0,
                sender_task: 0,
                sender_generation: 0,
                receiver_task: 0,
                receiver_generation: 0,
                occupied: false,
                payload: 0,
            },
            manifest: ManifestPublication::EMPTY,
            broker: ApprovalBroker::DEAD,
            effect: SyntheticEffect::EMPTY,
        }
    }

    fn unpublished_supervised(supervisor: TaskContextV1, workload: TaskContextV1) -> Self {
        Self {
            profile: RuntimeProfile::Supervised,
            tasks: [
                TaskSlot {
                    id: SENDER_TASK_ID,
                    generation: supervisor.generation,
                    state: TaskState::Ready,
                    context: supervisor,
                    capabilities: CapabilityTable::building(SENDER_TASK_ID, supervisor.generation),
                },
                TaskSlot {
                    id: RECEIVER_TASK_ID,
                    generation: workload.generation,
                    state: TaskState::Staged,
                    context: workload,
                    capabilities: CapabilityTable::building(RECEIVER_TASK_ID, workload.generation),
                },
            ],
            queue: RunQueue::new(),
            endpoint: EndpointSnapshot {
                object_generation: 0,
                sender_task: 0,
                sender_generation: 0,
                receiver_task: 0,
                receiver_generation: 0,
                occupied: false,
                payload: 0,
            },
            manifest: ManifestPublication::EMPTY,
            broker: ApprovalBroker::building(supervisor.generation, workload.generation),
            effect: SyntheticEffect {
                object_generation: FIXED_OBJECT_GENERATION,
                supervisor_task_id: SENDER_TASK_ID,
                supervisor_generation: supervisor.generation,
                occupied: false,
                value: 0,
            },
        }
    }

    fn publish_initial(&mut self, fail_before_step: Option<usize>) -> Result<(), RuntimeError> {
        let mut installed = [(0_u64, 0_u64); TASK_COUNT];
        let mut installed_len = 0;
        for (step, task, rights) in [
            (
                0,
                SENDER_TASK_ID,
                CAPABILITY_RIGHT_SEND | CAPABILITY_RIGHT_DUPLICATE,
            ),
            (1, RECEIVER_TASK_ID, CAPABILITY_RIGHT_RECEIVE),
        ] {
            if fail_before_step == Some(step) {
                self.rollback_publication(&installed, installed_len);
                return Err(RuntimeError::PublicationFailure);
            }
            let handle = match self
                .slot_mut(task)
                .and_then(|slot| slot.capabilities.install_building(rights))
            {
                Ok(handle) => handle,
                Err(error) => {
                    self.rollback_publication(&installed, installed_len);
                    return Err(error);
                }
            };
            installed[installed_len] = (task, handle);
            installed_len += 1;
        }
        if fail_before_step == Some(2) {
            self.rollback_publication(&installed, installed_len);
            return Err(RuntimeError::PublicationFailure);
        }
        for task in [SENDER_TASK_ID, RECEIVER_TASK_ID] {
            if let Err(error) = self
                .slot_mut(task)
                .and_then(|slot| slot.capabilities.publish())
            {
                self.rollback_publication(&installed, installed_len);
                return Err(error);
            }
        }
        self.endpoint = EndpointSnapshot {
            object_generation: ENDPOINT_GENERATION,
            sender_task: SENDER_TASK_ID,
            sender_generation: self.tasks[0].generation,
            receiver_task: RECEIVER_TASK_ID,
            receiver_generation: self.tasks[1].generation,
            occupied: false,
            payload: 0,
        };
        if let Err(error) = self
            .queue
            .push(RECEIVER_TASK_ID)
            .and_then(|_| self.queue.push(SENDER_TASK_ID))
            .and_then(|_| self.validate())
        {
            self.rollback_publication(&installed, installed_len);
            return Err(error);
        }
        Ok(())
    }

    fn publish_supervisor(&mut self, fail_before_step: Option<usize>) -> Result<(), RuntimeError> {
        let mut installed = [0_u64; 3];
        let mut installed_len = 0;
        for (step, object_type, object_id, rights) in [
            (
                0,
                OBJECT_TYPE_TASK_CONTROL,
                TASK_CONTROL_OBJECT_ID,
                CAPABILITY_RIGHT_START,
            ),
            (
                1,
                OBJECT_TYPE_APPROVAL_BROKER,
                APPROVAL_BROKER_OBJECT_ID,
                CAPABILITY_RIGHT_DECIDE_APPROVAL,
            ),
            (
                2,
                OBJECT_TYPE_TEST_EFFECT,
                TEST_EFFECT_OBJECT_ID,
                CAPABILITY_RIGHT_COMMIT_EFFECT,
            ),
        ] {
            if fail_before_step == Some(step) {
                self.rollback_supervisor_publication(&installed, installed_len);
                return Err(RuntimeError::PublicationFailure);
            }
            let handle = match self.tasks[0].capabilities.install_object_building(
                object_type,
                ObjectReference {
                    id: object_id,
                    generation: FIXED_OBJECT_GENERATION,
                },
                rights,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    self.rollback_supervisor_publication(&installed, installed_len);
                    return Err(error);
                }
            };
            installed[installed_len] = handle;
            installed_len += 1;
        }
        if fail_before_step == Some(3) {
            self.rollback_supervisor_publication(&installed, installed_len);
            return Err(RuntimeError::PublicationFailure);
        }
        if let Err(error) = self.tasks[0].capabilities.publish() {
            self.rollback_supervisor_publication(&installed, installed_len);
            return Err(error);
        }
        self.broker.state = ApprovalBrokerState::Empty;
        if fail_before_step == Some(4) {
            self.rollback_supervisor_publication(&installed, installed_len);
            return Err(RuntimeError::PublicationFailure);
        }
        if let Err(error) = self
            .queue
            .push(SENDER_TASK_ID)
            .and_then(|_| self.validate())
        {
            self.rollback_supervisor_publication(&installed, installed_len);
            return Err(error);
        }
        Ok(())
    }

    fn rollback_supervisor_publication(&mut self, installed: &[u64; 3], len: usize) {
        for handle in installed[..len].iter().rev() {
            self.tasks[0].capabilities.rollback_install(*handle);
        }
        self.queue = RunQueue::new();
        self.manifest = ManifestPublication::EMPTY;
        self.broker = ApprovalBroker::DEAD;
        self.effect = SyntheticEffect::EMPTY;
        for slot in &mut self.tasks {
            slot.state = TaskState::Dead;
            slot.generation = 0;
            slot.context.clear_dead();
            slot.capabilities = CapabilityTable::dead();
        }
    }

    fn rollback_publication(&mut self, installed: &[(u64, u64); TASK_COUNT], len: usize) {
        for (task, handle) in installed[..len].iter().rev() {
            if let Ok(slot) = self.slot_mut(*task) {
                slot.capabilities.rollback_install(*handle);
            }
        }
        self.queue = RunQueue::new();
        self.endpoint = EndpointSnapshot {
            object_generation: 0,
            sender_task: 0,
            sender_generation: 0,
            receiver_task: 0,
            receiver_generation: 0,
            occupied: false,
            payload: 0,
        };
        self.manifest = ManifestPublication::EMPTY;
        self.broker = ApprovalBroker::DEAD;
        self.effect = SyntheticEffect::EMPTY;
        for slot in &mut self.tasks {
            slot.state = TaskState::Dead;
            slot.generation = 0;
            slot.context.clear_dead();
            slot.capabilities = CapabilityTable::dead();
        }
    }

    pub fn state(&self, task: u64) -> Result<TaskState, RuntimeError> {
        Ok(self.slot(task)?.state)
    }

    pub fn generation(&self, task: u64) -> Result<u64, RuntimeError> {
        Ok(self.slot(task)?.generation)
    }

    pub fn context(&self, task: u64) -> Result<&TaskContextV1, RuntimeError> {
        Ok(&self.slot(task)?.context)
    }

    pub fn queue(&self) -> ([u64; TASK_COUNT], usize) {
        (self.queue.as_array(), self.queue.len)
    }

    pub const fn endpoint(&self) -> EndpointSnapshot {
        self.endpoint
    }

    pub const fn profile(&self) -> RuntimeProfile {
        self.profile
    }

    pub const fn manifest_publication(&self) -> ManifestPublicationSnapshot {
        ManifestPublicationSnapshot {
            manifest_id: self.manifest.manifest_id,
            principal_id: self.manifest.principal_id,
            target_task_id: self.manifest.target_task_id,
            target_generation: self.manifest.target_generation,
            image_id: self.manifest.image_id,
            published: self.manifest.published,
        }
    }

    pub const fn approval_broker(&self) -> ApprovalBrokerSnapshot {
        ApprovalBrokerSnapshot {
            state: self.broker.state,
            object_generation: self.broker.object_generation,
            supervisor_task_id: self.broker.supervisor_task_id,
            supervisor_generation: self.broker.supervisor_generation,
            workload_task_id: self.broker.workload_task_id,
            workload_generation: self.broker.workload_generation,
            request_kind: self.broker.request_kind,
            request: self.broker.request,
            request_present: self.broker.request_present,
            next_sequence: self.broker.next_sequence,
            sequence_exhausted: self.broker.sequence_exhausted,
            decision_epoch: self.broker.decision_epoch,
            approval_epoch: self.broker.approval_epoch,
            expiry_epoch: self.broker.expiry_epoch,
        }
    }

    pub const fn synthetic_effect(&self) -> SyntheticEffectSnapshot {
        SyntheticEffectSnapshot {
            object_generation: self.effect.object_generation,
            supervisor_task_id: self.effect.supervisor_task_id,
            supervisor_generation: self.effect.supervisor_generation,
            occupied: self.effect.occupied,
            value: self.effect.value,
        }
    }

    pub fn capability_table(&self, task: u64) -> Result<CapabilityTableSnapshot, RuntimeError> {
        Ok(self.slot(task)?.capabilities.snapshot())
    }

    pub fn running_task(&self) -> Result<u64, RuntimeError> {
        let mut running = 0;
        for slot in &self.tasks {
            if slot.state == TaskState::Running {
                if running != 0 {
                    return Err(RuntimeError::MultipleRunningTasks);
                }
                running = slot.id;
            }
        }
        if running == 0 {
            Err(RuntimeError::NoRunningTask)
        } else {
            Ok(running)
        }
    }

    pub fn dispatch_next(&mut self) -> Result<Option<u64>, RuntimeError> {
        if self
            .tasks
            .iter()
            .any(|slot| slot.state == TaskState::Running)
        {
            return Err(RuntimeError::WrongState);
        }
        let Some(task) = self.queue.pop() else {
            if self.tasks.iter().all(|slot| slot.state == TaskState::Dead) {
                return Ok(None);
            }
            return Err(RuntimeError::NoRunnableTask);
        };
        let slot = self.slot_mut(task)?;
        if slot.state != TaskState::Ready {
            return Err(RuntimeError::InvalidQueueMember);
        }
        slot.state = TaskState::Running;
        self.validate()?;
        Ok(Some(task))
    }

    pub fn capture_trap(
        &mut self,
        task: u64,
        frame: TrapFrameV1,
        root: u64,
        generation: u64,
    ) -> Result<(), RuntimeError> {
        let slot = self.slot_mut(task)?;
        if slot.state != TaskState::Running || slot.generation != generation {
            return Err(RuntimeError::WrongState);
        }
        slot.context = TaskContextV1::from_trap(frame, task, generation, root);
        Ok(())
    }

    pub fn handle_trap(&mut self, task: u64) -> Result<TrapOutcome, RuntimeError> {
        let before = *self;
        let result = self.handle_trap_inner(task);
        if result.is_err() {
            *self = before;
        }
        result
    }

    pub fn complete_teardown(&mut self, task: u64) -> Result<Option<u64>, RuntimeError> {
        let before = *self;
        let result = self.complete_teardown_inner(task);
        if result.is_err() {
            *self = before;
        }
        result
    }

    pub fn begin_teardown(&mut self, task: u64) -> Result<(), RuntimeError> {
        let before = *self;
        let result = self.begin_teardown_inner(task);
        if result.is_err() {
            *self = before;
        }
        result
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.queue.len > TASK_COUNT
            || self.queue.entries[self.queue.len..]
                .iter()
                .any(|entry| *entry != 0)
        {
            return Err(RuntimeError::InvalidQueueMember);
        }
        for (index, task) in self.queue.entries[..self.queue.len].iter().enumerate() {
            if !matches!(*task, SENDER_TASK_ID | RECEIVER_TASK_ID)
                || self.queue.entries[index + 1..self.queue.len].contains(task)
            {
                return Err(RuntimeError::DuplicateQueueMember);
            }
        }
        let running = self
            .tasks
            .iter()
            .filter(|slot| slot.state == TaskState::Running)
            .count();
        if running > 1 {
            return Err(RuntimeError::MultipleRunningTasks);
        }
        for slot in &self.tasks {
            slot.capabilities.validate()?;
            let queued = self.queue.contains(slot.id);
            if (slot.state == TaskState::Ready) != queued {
                return Err(if queued {
                    RuntimeError::InvalidQueueMember
                } else {
                    RuntimeError::MissingQueueMember
                });
            }
            if slot.state == TaskState::Dead {
                if slot.generation != 0
                    || slot.context.task_id != 0
                    || slot.context.generation != 0
                    || slot.context.root != 0
                    || slot.capabilities.state != CapabilityTableState::Dead
                {
                    return Err(RuntimeError::InvalidGeneration);
                }
            } else if slot.generation == 0
                || slot.context.task_id != slot.id
                || slot.context.generation != slot.generation
                || slot.context.root == 0
                || slot.capabilities.task_id != slot.id
                || slot.capabilities.task_generation != slot.generation
            {
                return Err(RuntimeError::InvalidGeneration);
            }
            let expected_table_state = match slot.state {
                TaskState::Staged => CapabilityTableState::Building,
                TaskState::Ready
                | TaskState::Running
                | TaskState::BlockedReceive
                | TaskState::BlockedApproval => CapabilityTableState::Live,
                TaskState::Exited => {
                    if !matches!(
                        slot.capabilities.state,
                        CapabilityTableState::Live | CapabilityTableState::Closing
                    ) {
                        return Err(RuntimeError::CapabilityInvariant);
                    }
                    slot.capabilities.state
                }
                TaskState::Dead => CapabilityTableState::Dead,
            };
            if slot.capabilities.state != expected_table_state {
                return Err(RuntimeError::CapabilityInvariant);
            }
        }
        match self.profile {
            RuntimeProfile::Cooperative => self.validate_cooperative(),
            RuntimeProfile::Supervised => self.validate_supervised(),
        }
    }

    fn validate_cooperative(&self) -> Result<(), RuntimeError> {
        if self
            .tasks
            .iter()
            .any(|slot| matches!(slot.state, TaskState::Staged | TaskState::BlockedApproval))
            || self.manifest != ManifestPublication::EMPTY
            || self.broker != ApprovalBroker::DEAD
            || self.effect != SyntheticEffect::EMPTY
        {
            return Err(RuntimeError::CapabilityInvariant);
        }
        let sender = &self.tasks[0];
        let receiver = &self.tasks[1];
        if sender.capabilities.state == CapabilityTableState::Live
            && (self.endpoint.sender_task != sender.id
                || self.endpoint.sender_generation != sender.generation)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if matches!(
            sender.capabilities.state,
            CapabilityTableState::Closing | CapabilityTableState::Dead
        ) && (self.endpoint.sender_task != 0 || self.endpoint.sender_generation != 0)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if receiver.capabilities.state == CapabilityTableState::Live
            && (self.endpoint.receiver_task != receiver.id
                || self.endpoint.receiver_generation != receiver.generation)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if matches!(
            receiver.capabilities.state,
            CapabilityTableState::Closing | CapabilityTableState::Dead
        ) && (self.endpoint.receiver_task != 0 || self.endpoint.receiver_generation != 0)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if receiver.state == TaskState::BlockedReceive
            && (self.endpoint.occupied || self.endpoint.sender_generation == 0)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if self.endpoint.receiver_generation == 0 && self.endpoint.occupied {
            return Err(RuntimeError::EndpointInvariant);
        }
        if (!self.endpoint.occupied && self.endpoint.payload != 0)
            || !matches!(self.endpoint.object_generation, 0 | ENDPOINT_GENERATION)
            || (self.tasks.iter().any(|slot| slot.state != TaskState::Dead)
                && self.endpoint.object_generation != ENDPOINT_GENERATION)
            || ((self.endpoint.sender_task == 0) != (self.endpoint.sender_generation == 0))
            || ((self.endpoint.receiver_task == 0) != (self.endpoint.receiver_generation == 0))
            || !matches!(self.endpoint.sender_task, 0 | SENDER_TASK_ID)
            || !matches!(self.endpoint.receiver_task, 0 | RECEIVER_TASK_ID)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        if self.tasks.iter().all(|slot| slot.state == TaskState::Dead)
            && self.endpoint
                != (EndpointSnapshot {
                    object_generation: 0,
                    sender_task: 0,
                    sender_generation: 0,
                    receiver_task: 0,
                    receiver_generation: 0,
                    occupied: false,
                    payload: 0,
                })
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        Ok(())
    }

    fn validate_supervised(&self) -> Result<(), RuntimeError> {
        const EMPTY_ENDPOINT: EndpointSnapshot = EndpointSnapshot {
            object_generation: 0,
            sender_task: 0,
            sender_generation: 0,
            receiver_task: 0,
            receiver_generation: 0,
            occupied: false,
            payload: 0,
        };
        if self.endpoint != EMPTY_ENDPOINT
            || self
                .tasks
                .iter()
                .any(|slot| slot.state == TaskState::BlockedReceive)
        {
            return Err(RuntimeError::EndpointInvariant);
        }
        let supervisor = &self.tasks[0];
        let workload = &self.tasks[1];
        if supervisor.state != TaskState::Dead && supervisor.generation != SUPERVISOR_GENERATION {
            return Err(RuntimeError::InvalidGeneration);
        }
        if workload.state != TaskState::Dead && workload.generation != WORKLOAD_GENERATION {
            return Err(RuntimeError::InvalidGeneration);
        }
        if workload.state == TaskState::Staged {
            if self.manifest != ManifestPublication::EMPTY
                || workload.capabilities.state != CapabilityTableState::Building
                || workload.capabilities.snapshot().live_slots != 0
            {
                return Err(RuntimeError::ManifestInvariant);
            }
        } else if workload.state != TaskState::Dead
            && workload.capabilities.state != CapabilityTableState::Closing
            && (!self.manifest.published
                || self.manifest.manifest_id != MANIFEST_ID
                || self.manifest.principal_id != PRINCIPAL_ID
                || self.manifest.target_task_id != RECEIVER_TASK_ID
                || self.manifest.target_generation != WORKLOAD_GENERATION
                || self.manifest.image_id != WORKLOAD_IMAGE_ID)
        {
            return Err(RuntimeError::ManifestInvariant);
        }
        if workload.state == TaskState::Dead && self.manifest != ManifestPublication::EMPTY {
            return Err(RuntimeError::ManifestInvariant);
        }

        match self.broker.state {
            ApprovalBrokerState::Building => return Err(RuntimeError::BrokerInvariant),
            ApprovalBrokerState::Empty => {
                if self.broker.request_present
                    || self.broker.request_kind != 0
                    || self.broker.request != ApprovalRequestV1::default()
                    || self.broker.approval_epoch != 0
                    || self.broker.expiry_epoch != 0
                {
                    return Err(RuntimeError::BrokerInvariant);
                }
            }
            ApprovalBrokerState::Pending => {
                if !self.broker.request_present
                    || self.broker.request_kind != APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE
                    || self.broker.approval_epoch != 0
                    || self.broker.expiry_epoch != 0
                    || workload.state != TaskState::BlockedApproval
                {
                    return Err(RuntimeError::BrokerInvariant);
                }
            }
            ApprovalBrokerState::Approved => {
                if !self.broker.request_present
                    || self.broker.request_kind != APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE
                    || self.broker.approval_epoch == 0
                    || self.broker.expiry_epoch != self.broker.approval_epoch.saturating_add(1)
                    || workload.state != TaskState::BlockedApproval
                {
                    return Err(RuntimeError::BrokerInvariant);
                }
            }
            ApprovalBrokerState::Closing | ApprovalBrokerState::Dead => {
                if self.broker.request_present
                    || self.broker.request_kind != 0
                    || self.broker.request != ApprovalRequestV1::default()
                    || self.broker.approval_epoch != 0
                    || self.broker.expiry_epoch != 0
                {
                    return Err(RuntimeError::BrokerInvariant);
                }
            }
        }
        if self.broker.state != ApprovalBrokerState::Dead {
            if self.broker.object_generation != FIXED_OBJECT_GENERATION
                || self.broker.next_sequence == 0
                || self.broker.decision_epoch == 0
            {
                return Err(RuntimeError::BrokerInvariant);
            }
        } else if self.broker != ApprovalBroker::DEAD {
            return Err(RuntimeError::BrokerInvariant);
        }
        if self.broker.request_present {
            let request = self.broker.request;
            if request.principal_id != PRINCIPAL_ID
                || request.workload_task_id != RECEIVER_TASK_ID
                || request.workload_generation != WORKLOAD_GENERATION
                || request.sequence == 0
                || request.action_id != APPROVAL_ACTION_ID_COMMIT_SYNTHETIC_VALUE
                || request.effect_object_id != TEST_EFFECT_OBJECT_ID
                || request.effect_object_generation != FIXED_OBJECT_GENERATION
                || request.requested_rights != CAPABILITY_RIGHT_COMMIT_EFFECT
                || request.resulting_rights != 0
            {
                return Err(RuntimeError::BrokerInvariant);
            }
        }
        if self.effect.object_generation == 0 {
            if self.effect != SyntheticEffect::EMPTY {
                return Err(RuntimeError::EffectInvariant);
            }
        } else if self.effect.object_generation != FIXED_OBJECT_GENERATION
            || self.effect.supervisor_task_id != SENDER_TASK_ID
            || self.effect.supervisor_generation != SUPERVISOR_GENERATION
            || (!self.effect.occupied && self.effect.value != 0)
        {
            return Err(RuntimeError::EffectInvariant);
        }
        if self.tasks.iter().all(|slot| slot.state == TaskState::Dead)
            && (self.manifest != ManifestPublication::EMPTY
                || self.broker != ApprovalBroker::DEAD
                || self.effect != SyntheticEffect::EMPTY)
        {
            return Err(RuntimeError::BrokerInvariant);
        }
        Ok(())
    }

    fn handle_trap_inner(&mut self, task: u64) -> Result<TrapOutcome, RuntimeError> {
        if self.running_task()? != task {
            return Err(RuntimeError::WrongState);
        }
        let input = *self.context(task)?;
        let Some(operation) = TrapOperation::parse(input.rax) else {
            self.set_result(task, TrapStatus::InvalidOperation, 0)?;
            return Ok(TrapOutcome::Resume(task));
        };
        match operation {
            TrapOperation::Yield => {
                if input.rdi != 0 || input.rsi != 0 || input.rdx != 0 {
                    self.set_result(task, TrapStatus::InvalidOperation, 0)?;
                    return Ok(TrapOutcome::Resume(task));
                }
                self.set_result(task, TrapStatus::Ok, 0)?;
                self.slot_mut(task)?.state = TaskState::Ready;
                self.queue.push(task)?;
                let next = self.dispatch_next()?.ok_or(RuntimeError::NoRunnableTask)?;
                Ok(TrapOutcome::Switch(next))
            }
            TrapOperation::Send => self.send(task, input.rdi, input.rsi, input.rdx),
            TrapOperation::Receive => self.receive(task, input.rdi, input.rsi, input.rdx),
            TrapOperation::Exit => self.exit(task, input.rdi, input.rsi, input.rdx),
            TrapOperation::Duplicate => self.duplicate(task, input.rdi, input.rsi, input.rdx),
            TrapOperation::Close => self.close(task, input.rdi, input.rsi, input.rdx),
            TrapOperation::StartWorkload => {
                self.start_workload(task, input.rdi, input.rsi, input.rdx)
            }
            TrapOperation::SubmitApproval => {
                self.submit_approval(task, input.rdi, input.rsi, input.rdx)
            }
            TrapOperation::InspectApproval => {
                self.inspect_approval(task, input.rdi, input.rsi, input.rdx)
            }
            TrapOperation::DecideApproval => {
                self.decide_approval(task, input.rdi, input.rsi, input.rdx)
            }
            TrapOperation::CommitEffect => {
                self.commit_effect(task, input.rdi, input.rsi, input.rdx)
            }
        }
    }

    fn send(
        &mut self,
        task: u64,
        handle: u64,
        message: u64,
        reserved: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if reserved != 0 {
            TrapStatus::InvalidOperation
        } else if let Err(status) = self.resolve_endpoint(task, handle, CAPABILITY_RIGHT_SEND) {
            status
        } else if self.endpoint.receiver_generation == 0 {
            TrapStatus::PeerExited
        } else if self.endpoint.occupied {
            TrapStatus::SlotFull
        } else {
            self.endpoint.occupied = true;
            self.endpoint.payload = message;
            if self.slot(RECEIVER_TASK_ID)?.state == TaskState::BlockedReceive {
                let value = self.endpoint.payload;
                self.endpoint.occupied = false;
                self.endpoint.payload = 0;
                self.set_result(RECEIVER_TASK_ID, TrapStatus::Ok, value)?;
                self.slot_mut(RECEIVER_TASK_ID)?.state = TaskState::Ready;
                self.queue.push(RECEIVER_TASK_ID)?;
            }
            TrapStatus::Ok
        };
        self.set_result(task, status, 0)?;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn receive(
        &mut self,
        task: u64,
        handle: u64,
        reserved_message: u64,
        reserved: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if reserved_message != 0 || reserved != 0 {
            Some(TrapStatus::InvalidOperation)
        } else {
            self.resolve_endpoint(task, handle, CAPABILITY_RIGHT_RECEIVE)
                .err()
        };
        if let Some(status) = status {
            self.set_result(task, status, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        if self.endpoint.occupied {
            let value = self.endpoint.payload;
            self.endpoint.occupied = false;
            self.endpoint.payload = 0;
            self.set_result(task, TrapStatus::Ok, value)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }
        if self.endpoint.sender_generation == 0 {
            self.set_result(task, TrapStatus::PeerExited, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.slot_mut(task)?.state = TaskState::BlockedReceive;
        let next = self.dispatch_next()?.ok_or(RuntimeError::NoRunnableTask)?;
        self.validate()?;
        Ok(TrapOutcome::Switch(next))
    }

    fn exit(
        &mut self,
        task: u64,
        first: u64,
        second: u64,
        third: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        if first != 0 || second != 0 || third != 0 {
            self.set_result(task, TrapStatus::InvalidOperation, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.slot_mut(task)?.state = TaskState::Exited;
        self.validate()?;
        Ok(TrapOutcome::Exit(task))
    }

    fn duplicate(
        &mut self,
        task: u64,
        source: u64,
        requested_rights: u64,
        reserved: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        if reserved != 0 {
            self.set_result(task, TrapStatus::InvalidOperation, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        let generation = self.slot(task)?.generation;
        let result =
            self.slot_mut(task)?
                .capabilities
                .duplicate(task, generation, source, requested_rights);
        match result {
            Ok(handle) => self.set_result(task, TrapStatus::Ok, handle)?,
            Err(status) => self.set_result(task, status, 0)?,
        }
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn close(
        &mut self,
        task: u64,
        handle: u64,
        reserved_rights: u64,
        reserved: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        if reserved_rights != 0 || reserved != 0 {
            self.set_result(task, TrapStatus::InvalidOperation, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        let generation = self.slot(task)?.generation;
        let status = match self
            .slot_mut(task)?
            .capabilities
            .close(task, generation, handle)
        {
            Ok(()) => TrapStatus::Ok,
            Err(status) => status,
        };
        self.set_result(task, status, 0)?;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn start_workload(
        &mut self,
        task: u64,
        handle: u64,
        manifest_id: u64,
        reserved: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        self.start_workload_with_failure(task, handle, manifest_id, reserved, None)
    }

    fn start_workload_with_failure(
        &mut self,
        task: u64,
        handle: u64,
        manifest_id: u64,
        reserved: u64,
        fail_before_step: Option<usize>,
    ) -> Result<TrapOutcome, RuntimeError> {
        let before = *self;
        let status = if reserved != 0 {
            Some(TrapStatus::InvalidOperation)
        } else if self.profile != RuntimeProfile::Supervised {
            Some(TrapStatus::WrongObject)
        } else if let Err(status) = self.resolve_object(
            task,
            handle,
            OBJECT_TYPE_TASK_CONTROL,
            CAPABILITY_RIGHT_START,
            TASK_CONTROL_OBJECT_ID,
            FIXED_OBJECT_GENERATION,
        ) {
            Some(status)
        } else if manifest_id != MANIFEST_ID {
            Some(TrapStatus::InvalidManifest)
        } else if self.tasks[1].state != TaskState::Staged {
            Some(TrapStatus::AlreadyLaunched)
        } else if REGISTERED_LAUNCH_MANIFEST
            .validate(
                self.tasks[1].generation,
                self.broker.object_generation,
                self.tasks[1].capabilities.available_slots(),
            )
            .is_err()
        {
            Some(TrapStatus::InvalidManifest)
        } else {
            None
        };
        if let Some(status) = status {
            *self = before;
            self.set_result(task, status, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }

        if fail_before_step == Some(0) {
            *self = before;
            self.set_result(task, TrapStatus::InvalidManifest, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }

        for route in
            &REGISTERED_LAUNCH_MANIFEST.routes[..REGISTERED_LAUNCH_MANIFEST.route_count as usize]
        {
            if self.tasks[1]
                .capabilities
                .install_object_building(
                    route.object_type,
                    ObjectReference {
                        id: route.object_id,
                        generation: route.object_generation,
                    },
                    route.rights,
                )
                .is_err()
            {
                *self = before;
                self.set_result(task, TrapStatus::InvalidManifest, 0)?;
                return Ok(TrapOutcome::Resume(task));
            }
        }
        if fail_before_step == Some(1) {
            *self = before;
            self.set_result(task, TrapStatus::InvalidManifest, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        if self.tasks[1].capabilities.publish().is_err() {
            *self = before;
            self.set_result(task, TrapStatus::InvalidManifest, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        if fail_before_step == Some(2) {
            *self = before;
            self.set_result(task, TrapStatus::InvalidManifest, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.manifest = ManifestPublication {
            manifest_id: MANIFEST_ID,
            principal_id: PRINCIPAL_ID,
            target_task_id: RECEIVER_TASK_ID,
            target_generation: WORKLOAD_GENERATION,
            image_id: WORKLOAD_IMAGE_ID,
            published: true,
        };
        self.tasks[1].state = TaskState::Ready;
        if fail_before_step == Some(3) {
            *self = before;
            self.set_result(task, TrapStatus::InvalidManifest, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.queue.push(RECEIVER_TASK_ID)?;
        self.set_result(task, TrapStatus::Ok, 0)?;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn submit_approval(
        &mut self,
        task: u64,
        handle: u64,
        request_kind: u64,
        argument: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if self.profile != RuntimeProfile::Supervised {
            Some(TrapStatus::WrongObject)
        } else if let Err(status) = self.resolve_object(
            task,
            handle,
            OBJECT_TYPE_APPROVAL_BROKER,
            CAPABILITY_RIGHT_SUBMIT_APPROVAL,
            APPROVAL_BROKER_OBJECT_ID,
            self.broker.object_generation,
        ) {
            Some(status)
        } else if matches!(
            self.broker.state,
            ApprovalBrokerState::Building
                | ApprovalBrokerState::Closing
                | ApprovalBrokerState::Dead
        ) || self.broker.sequence_exhausted
            || self.broker.decision_epoch == u64::MAX
        {
            Some(TrapStatus::BrokerUnavailable)
        } else if matches!(
            self.broker.state,
            ApprovalBrokerState::Pending | ApprovalBrokerState::Approved
        ) {
            Some(TrapStatus::BrokerFull)
        } else if request_kind != APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE
            || task != RECEIVER_TASK_ID
            || self.manifest
                != (ManifestPublication {
                    manifest_id: MANIFEST_ID,
                    principal_id: PRINCIPAL_ID,
                    target_task_id: RECEIVER_TASK_ID,
                    target_generation: WORKLOAD_GENERATION,
                    image_id: WORKLOAD_IMAGE_ID,
                    published: true,
                })
        {
            Some(TrapStatus::InvalidRequest)
        } else {
            None
        };
        if let Some(status) = status {
            self.set_result(task, status, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }

        let sequence = self.broker.next_sequence;
        let next_epoch = self
            .broker
            .decision_epoch
            .checked_add(1)
            .ok_or(RuntimeError::BrokerInvariant)?;
        self.broker.request_kind = request_kind;
        self.broker.request = ApprovalRequestV1 {
            principal_id: PRINCIPAL_ID,
            workload_task_id: RECEIVER_TASK_ID,
            workload_generation: WORKLOAD_GENERATION,
            sequence,
            action_id: APPROVAL_ACTION_ID_COMMIT_SYNTHETIC_VALUE,
            effect_object_id: TEST_EFFECT_OBJECT_ID,
            effect_object_generation: FIXED_OBJECT_GENERATION,
            argument,
            requested_rights: CAPABILITY_RIGHT_COMMIT_EFFECT,
            resulting_rights: 0,
        };
        self.broker.request_present = true;
        self.broker.state = ApprovalBrokerState::Pending;
        self.broker.decision_epoch = next_epoch;
        if sequence == u64::MAX {
            self.broker.sequence_exhausted = true;
        } else {
            self.broker.next_sequence = sequence + 1;
        }
        self.slot_mut(task)?.state = TaskState::BlockedApproval;
        let next = self.dispatch_next()?.ok_or(RuntimeError::NoRunnableTask)?;
        self.validate()?;
        Ok(TrapOutcome::Switch(next))
    }

    fn inspect_approval(
        &mut self,
        task: u64,
        handle: u64,
        reserved_kind: u64,
        reserved_argument: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if reserved_kind != 0 || reserved_argument != 0 {
            Some(TrapStatus::InvalidOperation)
        } else if self.profile != RuntimeProfile::Supervised {
            Some(TrapStatus::WrongObject)
        } else if let Err(status) = self.resolve_object(
            task,
            handle,
            OBJECT_TYPE_APPROVAL_BROKER,
            CAPABILITY_RIGHT_DECIDE_APPROVAL,
            APPROVAL_BROKER_OBJECT_ID,
            self.broker.object_generation,
        ) {
            Some(status)
        } else if self.broker.state != ApprovalBrokerState::Pending || !self.broker.request_present
        {
            Some(
                if matches!(
                    self.broker.state,
                    ApprovalBrokerState::Closing | ApprovalBrokerState::Dead
                ) {
                    TrapStatus::BrokerUnavailable
                } else {
                    TrapStatus::InvalidRequest
                },
            )
        } else {
            None
        };
        if let Some(status) = status {
            self.set_result(task, status, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }
        let request = self.broker.request;
        let request_kind = self.broker.request_kind;
        let context = &mut self.slot_mut(task)?.context;
        context.rax = TrapStatus::Ok as u64;
        context.rdi = request.sequence;
        context.rsi = request_kind;
        context.rdx = request.argument;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn decide_approval(
        &mut self,
        task: u64,
        handle: u64,
        sequence: u64,
        decision: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if self.profile != RuntimeProfile::Supervised {
            Some(TrapStatus::WrongObject)
        } else if let Err(status) = self.resolve_object(
            task,
            handle,
            OBJECT_TYPE_APPROVAL_BROKER,
            CAPABILITY_RIGHT_DECIDE_APPROVAL,
            APPROVAL_BROKER_OBJECT_ID,
            self.broker.object_generation,
        ) {
            Some(status)
        } else if matches!(
            self.broker.state,
            ApprovalBrokerState::Closing | ApprovalBrokerState::Dead
        ) {
            Some(TrapStatus::BrokerUnavailable)
        } else if !self.broker.request_present || self.broker.request.sequence != sequence {
            Some(TrapStatus::ApprovalMismatch)
        } else if !matches!(decision, DECISION_DENY | DECISION_APPROVE | DECISION_EXPIRE)
            || (decision == DECISION_APPROVE && self.broker.state != ApprovalBrokerState::Pending)
            || (decision == DECISION_DENY && self.broker.state != ApprovalBrokerState::Pending)
            || (decision == DECISION_EXPIRE
                && !matches!(
                    self.broker.state,
                    ApprovalBrokerState::Pending | ApprovalBrokerState::Approved
                ))
        {
            Some(TrapStatus::InvalidRequest)
        } else {
            None
        };
        if let Some(status) = status {
            self.set_result(task, status, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }

        let reserve_expiry = decision == DECISION_APPROVE;
        let Some(next_epoch) = self.broker.decision_epoch.checked_add(1) else {
            self.fail_broker_epoch_exhaustion()?;
            self.set_result(task, TrapStatus::BrokerUnavailable, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        };
        if reserve_expiry && next_epoch == u64::MAX {
            self.fail_broker_epoch_exhaustion()?;
            self.set_result(task, TrapStatus::BrokerUnavailable, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.broker.decision_epoch = next_epoch;
        match decision {
            DECISION_APPROVE => {
                self.broker.state = ApprovalBrokerState::Approved;
                self.broker.approval_epoch = next_epoch;
                self.broker.expiry_epoch = next_epoch + 1;
            }
            DECISION_DENY => {
                self.broker.clear_request();
                self.broker.state = ApprovalBrokerState::Empty;
                self.wake_workload(TrapStatus::ApprovalDenied, 0)?;
            }
            DECISION_EXPIRE => {
                self.broker.clear_request();
                self.broker.state = ApprovalBrokerState::Empty;
                self.wake_workload(TrapStatus::ApprovalExpired, 0)?;
            }
            _ => return Err(RuntimeError::BrokerInvariant),
        }
        self.set_result(task, TrapStatus::Ok, 0)?;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn commit_effect(
        &mut self,
        task: u64,
        handle: u64,
        sequence: u64,
        argument: u64,
    ) -> Result<TrapOutcome, RuntimeError> {
        let status = if self.profile != RuntimeProfile::Supervised {
            Some(TrapStatus::WrongObject)
        } else if let Err(status) = self.resolve_object(
            task,
            handle,
            OBJECT_TYPE_TEST_EFFECT,
            CAPABILITY_RIGHT_COMMIT_EFFECT,
            TEST_EFFECT_OBJECT_ID,
            self.effect.object_generation,
        ) {
            Some(status)
        } else if self.broker.state != ApprovalBrokerState::Approved
            || !self.broker.request_present
            || self.broker.request.sequence != sequence
            || self.broker.request.argument != argument
            || self.broker.request.principal_id != PRINCIPAL_ID
            || self.broker.request.workload_task_id != RECEIVER_TASK_ID
            || self.broker.request.workload_generation != WORKLOAD_GENERATION
            || self.broker.request.action_id != APPROVAL_ACTION_ID_COMMIT_SYNTHETIC_VALUE
            || self.broker.request.effect_object_id != TEST_EFFECT_OBJECT_ID
            || self.broker.request.effect_object_generation != FIXED_OBJECT_GENERATION
            || self.broker.request.requested_rights != CAPABILITY_RIGHT_COMMIT_EFFECT
            || self.broker.request.resulting_rights != 0
        {
            Some(TrapStatus::ApprovalMismatch)
        } else if self.effect.occupied {
            Some(TrapStatus::EffectUnavailable)
        } else if self.broker.decision_epoch >= self.broker.expiry_epoch {
            Some(TrapStatus::ApprovalExpired)
        } else {
            None
        };
        if let Some(status) = status {
            self.set_result(task, status, 0)?;
            self.validate()?;
            return Ok(TrapOutcome::Resume(task));
        }
        let next_epoch = self
            .broker
            .decision_epoch
            .checked_add(1)
            .ok_or(RuntimeError::BrokerInvariant)?;
        if next_epoch != self.broker.expiry_epoch {
            self.set_result(task, TrapStatus::ApprovalExpired, 0)?;
            return Ok(TrapOutcome::Resume(task));
        }
        self.effect.occupied = true;
        self.effect.value = argument;
        self.broker.decision_epoch = next_epoch;
        self.broker.clear_request();
        self.broker.state = ApprovalBrokerState::Empty;
        self.wake_workload(TrapStatus::Ok, argument)?;
        self.set_result(task, TrapStatus::Ok, 0)?;
        self.validate()?;
        Ok(TrapOutcome::Resume(task))
    }

    fn wake_workload(&mut self, status: TrapStatus, value: u64) -> Result<(), RuntimeError> {
        if self.slot(RECEIVER_TASK_ID)?.state != TaskState::BlockedApproval {
            return Err(RuntimeError::BrokerInvariant);
        }
        self.set_result(RECEIVER_TASK_ID, status, value)?;
        self.slot_mut(RECEIVER_TASK_ID)?.state = TaskState::Ready;
        self.queue.push(RECEIVER_TASK_ID)
    }

    fn fail_broker_epoch_exhaustion(&mut self) -> Result<(), RuntimeError> {
        if self.slot(RECEIVER_TASK_ID)?.state == TaskState::BlockedApproval {
            self.wake_workload(TrapStatus::BrokerUnavailable, 0)?;
        }
        self.broker.clear_request();
        self.broker.state = ApprovalBrokerState::Closing;
        Ok(())
    }

    fn begin_teardown_inner(&mut self, task: u64) -> Result<(), RuntimeError> {
        if self.slot(task)?.state != TaskState::Exited {
            return Err(RuntimeError::WrongState);
        }
        if self.profile == RuntimeProfile::Supervised {
            self.slot_mut(task)?.capabilities.mark_closing()?;
            match task {
                SENDER_TASK_ID => {
                    if self.slot(RECEIVER_TASK_ID)?.state == TaskState::BlockedApproval {
                        let terminal = match self.broker.state {
                            ApprovalBrokerState::Pending => TrapStatus::ApprovalDenied,
                            ApprovalBrokerState::Approved => TrapStatus::ApprovalExpired,
                            _ => TrapStatus::BrokerUnavailable,
                        };
                        self.wake_workload(terminal, 0)?;
                    }
                    self.broker.clear_request();
                    self.broker.state = ApprovalBrokerState::Closing;
                    self.broker.supervisor_task_id = 0;
                    self.broker.supervisor_generation = 0;
                    self.effect = SyntheticEffect::EMPTY;
                }
                RECEIVER_TASK_ID => {
                    self.manifest = ManifestPublication::EMPTY;
                    self.broker.clear_request();
                    if !matches!(
                        self.broker.state,
                        ApprovalBrokerState::Closing | ApprovalBrokerState::Dead
                    ) {
                        self.broker.state = if self.tasks[0].state == TaskState::Dead {
                            ApprovalBrokerState::Closing
                        } else {
                            ApprovalBrokerState::Empty
                        };
                    }
                    self.broker.workload_task_id = 0;
                    self.broker.workload_generation = 0;
                }
                _ => return Err(RuntimeError::InvalidTask),
            }
            self.slot_mut(task)?.capabilities.close_all()?;
            self.validate()?;
            return Ok(());
        }

        self.slot_mut(task)?.capabilities.begin_closing()?;
        match task {
            SENDER_TASK_ID => {
                self.endpoint.sender_task = 0;
                self.endpoint.sender_generation = 0;
                if !self.endpoint.occupied
                    && self.slot(RECEIVER_TASK_ID)?.state == TaskState::BlockedReceive
                {
                    self.set_result(RECEIVER_TASK_ID, TrapStatus::PeerExited, 0)?;
                    self.slot_mut(RECEIVER_TASK_ID)?.state = TaskState::Ready;
                    self.queue.push(RECEIVER_TASK_ID)?;
                }
            }
            RECEIVER_TASK_ID => {
                self.endpoint.receiver_task = 0;
                self.endpoint.receiver_generation = 0;
                self.endpoint.occupied = false;
                self.endpoint.payload = 0;
            }
            _ => return Err(RuntimeError::InvalidTask),
        }
        self.validate()?;
        Ok(())
    }

    fn complete_teardown_inner(&mut self, task: u64) -> Result<Option<u64>, RuntimeError> {
        let slot = self.slot_mut(task)?;
        if slot.state != TaskState::Exited
            || slot.capabilities.state != CapabilityTableState::Closing
        {
            return Err(RuntimeError::WrongState);
        }
        slot.capabilities.finish_dead()?;
        slot.state = TaskState::Dead;
        slot.generation = 0;
        slot.context.clear_dead();
        if self.profile == RuntimeProfile::Supervised && task == SENDER_TASK_ID {
            self.broker = ApprovalBroker::DEAD;
            self.effect = SyntheticEffect::EMPTY;
        }
        if self.tasks.iter().all(|task| task.state == TaskState::Dead) {
            self.endpoint = EndpointSnapshot {
                object_generation: 0,
                sender_task: 0,
                sender_generation: 0,
                receiver_task: 0,
                receiver_generation: 0,
                occupied: false,
                payload: 0,
            };
            self.manifest = ManifestPublication::EMPTY;
            self.broker = ApprovalBroker::DEAD;
            self.effect = SyntheticEffect::EMPTY;
        }
        self.validate()?;
        self.dispatch_next()
    }

    fn resolve_endpoint(
        &self,
        task: u64,
        handle: u64,
        required_right: u64,
    ) -> Result<(), TrapStatus> {
        let slot = self.slot(task).map_err(|_| TrapStatus::InvalidHandle)?;
        let entry = slot
            .capabilities
            .resolve(task, slot.generation, handle, required_right)?;
        if entry.object.id != ENDPOINT_ID
            || entry.object.generation != ENDPOINT_GENERATION
            || self.endpoint.object_generation != ENDPOINT_GENERATION
        {
            return Err(TrapStatus::InvalidHandle);
        }
        Ok(())
    }

    fn resolve_object(
        &self,
        task: u64,
        handle: u64,
        object_type: u32,
        required_right: u64,
        object_id: u64,
        object_generation: u64,
    ) -> Result<(), TrapStatus> {
        let slot = self.slot(task).map_err(|_| TrapStatus::InvalidHandle)?;
        let entry = slot.capabilities.resolve_typed(
            task,
            slot.generation,
            handle,
            object_type,
            required_right,
        )?;
        if entry.object.id != object_id
            || entry.object.generation != object_generation
            || object_generation == 0
        {
            return Err(TrapStatus::InvalidHandle);
        }
        Ok(())
    }

    fn set_result(
        &mut self,
        task: u64,
        status: TrapStatus,
        value: u64,
    ) -> Result<(), RuntimeError> {
        self.slot_mut(task)?.context.set_result(status, value);
        Ok(())
    }

    fn slot(&self, task: u64) -> Result<&TaskSlot, RuntimeError> {
        match task {
            SENDER_TASK_ID => Ok(&self.tasks[0]),
            RECEIVER_TASK_ID => Ok(&self.tasks[1]),
            _ => Err(RuntimeError::InvalidTask),
        }
    }

    fn slot_mut(&mut self, task: u64) -> Result<&mut TaskSlot, RuntimeError> {
        match task {
            SENDER_TASK_ID => Ok(&mut self.tasks[0]),
            RECEIVER_TASK_ID => Ok(&mut self.tasks[1]),
            _ => Err(RuntimeError::InvalidTask),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const TEXT: u64 = 0x0000_0080_0040_0000;
    const STACK: u64 = 0x0000_0080_0080_0000;
    const STACK_TOP: u64 = STACK + 4096;
    const CODE: u64 = 0x23;
    const DATA: u64 = 0x1b;
    const MESSAGE: u64 = 0x0000_4d41_4b4f_5041;

    fn context(task: u64, generation: u64, root: u64) -> TaskContextV1 {
        TaskContextV1::initial(task, generation, root, TEXT, STACK_TOP, CODE, DATA)
    }

    fn runtime() -> Runtime {
        Runtime::new(context(1, 11, 0x1000), context(2, 12, 0x2000)).unwrap()
    }

    fn supervised_runtime() -> Runtime {
        Runtime::new_supervised(
            context(1, SUPERVISOR_GENERATION, 0x3000),
            context(2, WORKLOAD_GENERATION, 0x4000),
        )
        .unwrap()
    }

    fn install_call(runtime: &mut Runtime, task: u64, operation: u64, a: u64, b: u64, c: u64) {
        let slot = runtime.slot_mut(task).unwrap();
        slot.context.rax = operation;
        slot.context.rdi = a;
        slot.context.rsi = b;
        slot.context.rdx = c;
    }

    fn invoke(
        runtime: &mut Runtime,
        task: u64,
        operation: TrapOperation,
        a: u64,
        b: u64,
        c: u64,
    ) -> TrapOutcome {
        install_call(runtime, task, operation as u64, a, b, c);
        runtime.handle_trap(task).unwrap()
    }

    fn dispatch_sender(runtime: &mut Runtime) {
        assert_eq!(Some(RECEIVER_TASK_ID), runtime.dispatch_next().unwrap());
        assert_eq!(
            TrapOutcome::Switch(SENDER_TASK_ID),
            invoke(runtime, RECEIVER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );
    }

    fn launch_and_run_workload(runtime: &mut Runtime) {
        assert_eq!(Some(SENDER_TASK_ID), runtime.dispatch_next().unwrap());
        assert_eq!(
            TrapOutcome::Resume(SENDER_TASK_ID),
            invoke(
                runtime,
                SENDER_TASK_ID,
                TrapOperation::StartWorkload,
                SUPERVISOR_TASK_CONTROL_HANDLE,
                MANIFEST_ID,
                0,
            )
        );
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );
    }

    fn submit_and_inspect(runtime: &mut Runtime, argument: u64) -> u64 {
        assert_eq!(
            TrapOutcome::Switch(SENDER_TASK_ID),
            invoke(
                runtime,
                RECEIVER_TASK_ID,
                TrapOperation::SubmitApproval,
                WORKLOAD_APPROVAL_HANDLE,
                APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE,
                argument,
            )
        );
        assert_eq!(
            TrapOutcome::Resume(SENDER_TASK_ID),
            invoke(
                runtime,
                SENDER_TASK_ID,
                TrapOperation::InspectApproval,
                SUPERVISOR_DECISION_HANDLE,
                0,
                0,
            )
        );
        let context = runtime.context(SENDER_TASK_ID).unwrap();
        assert_eq!(TrapStatus::Ok as u64, context.rax);
        assert_eq!(APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE, context.rsi);
        assert_eq!(argument, context.rdx);
        context.rdi
    }

    #[test]
    fn initial_queue_is_receiver_then_sender_and_owner_pairs_are_exact() {
        let runtime = runtime();
        assert_eq!(([2, 1], 2), runtime.queue());
        assert_eq!(
            CapabilityTableSnapshot {
                task_id: 1,
                task_generation: 11,
                state: CapabilityTableState::Live,
                live_slots: 1,
                retired_slots: 0,
            },
            runtime.capability_table(1).unwrap()
        );
        assert_eq!(1, runtime.capability_table(2).unwrap().live_slots);
        assert_eq!(0x10, INITIAL_CAPABILITY_HANDLE);
        assert_eq!(OwnerPhase::Inactive, TaskState::Ready.owner_phase());
        assert_eq!(OwnerPhase::Active, TaskState::Running.owner_phase());
        assert_eq!(
            OwnerPhase::Inactive,
            TaskState::BlockedReceive.owner_phase()
        );
        assert_eq!(OwnerPhase::Teardown, TaskState::Exited.owner_phase());
        assert_eq!(OwnerPhase::Absent, TaskState::Dead.owner_phase());
        assert_eq!(0xee, DPL3_INTERRUPT_GATE_ATTRIBUTES);
        assert!(version_one_cr4_allowed(0));
        assert!(!version_one_cr4_allowed(CR4_FSGSBASE));
    }

    #[test]
    fn publication_rejects_wrong_ids_zero_or_duplicate_generations() {
        assert_eq!(
            Err(RuntimeError::InvalidTask),
            Runtime::new(context(2, 11, 0x1000), context(1, 12, 0x2000))
        );
        assert_eq!(
            Err(RuntimeError::InvalidGeneration),
            Runtime::new(context(1, 0, 0x1000), context(2, 12, 0x2000))
        );
        assert_eq!(
            Err(RuntimeError::DuplicateGeneration),
            Runtime::new(context(1, 11, 0x1000), context(2, 11, 0x2000))
        );
    }

    #[test]
    fn selector_encoding_is_exact_and_zero_or_out_of_range_parts_are_rejected() {
        for slot in 0..CAPABILITY_SLOT_COUNT {
            let handle = CapabilityHandleV1::from_parts(slot, 7).unwrap();
            assert_eq!((7 << 4) | slot as u64, handle.raw());
            assert_eq!(Some((slot, 7)), CapabilityHandleV1::decode(handle.raw()));
        }
        assert_eq!(
            None,
            CapabilityHandleV1::from_parts(CAPABILITY_SLOT_COUNT, 1)
        );
        assert_eq!(None, CapabilityHandleV1::from_parts(0, 0));
        assert_eq!(
            None,
            CapabilityHandleV1::from_parts(0, CAPABILITY_GENERATION_MAX + 1)
        );
        assert_eq!(None, CapabilityHandleV1::decode(0));
        assert_eq!(1, size_of::<CapabilityHandleV1>() / size_of::<u64>());
    }

    #[test]
    fn every_initial_table_failure_rolls_back_all_published_state() {
        for step in 0..=2 {
            let mut failed = Runtime::unpublished(context(1, 11, 0x1000), context(2, 12, 0x2000));
            let error = failed.publish_initial(Some(step)).unwrap_err();
            assert_eq!(RuntimeError::PublicationFailure, error);
            assert_eq!(([0, 0], 0), failed.queue());
            assert_eq!(0, failed.endpoint().object_generation);
            for task in [SENDER_TASK_ID, RECEIVER_TASK_ID] {
                assert_eq!(TaskState::Dead, failed.state(task).unwrap());
                assert_eq!(0, failed.generation(task).unwrap());
                assert_eq!(
                    CapabilityTableState::Dead,
                    failed.capability_table(task).unwrap().state
                );
                assert_eq!(0, failed.capability_table(task).unwrap().live_slots);
            }
            failed.validate().unwrap();
        }
    }

    #[test]
    fn attenuation_close_and_stale_rejection_preserve_independent_authority() {
        let mut runtime = runtime();
        dispatch_sender(&mut runtime);
        let original = INITIAL_CAPABILITY_HANDLE;
        for rights in [0, 1 << 8, CAPABILITY_RIGHT_SEND | CAPABILITY_RIGHT_RECEIVE] {
            let before = runtime.capability_table(SENDER_TASK_ID).unwrap();
            assert_eq!(
                TrapOutcome::Resume(SENDER_TASK_ID),
                invoke(
                    &mut runtime,
                    SENDER_TASK_ID,
                    TrapOperation::Duplicate,
                    original,
                    rights,
                    0,
                )
            );
            assert_eq!(
                TrapStatus::InvalidRights as u64,
                runtime.context(SENDER_TASK_ID).unwrap().rax
            );
            assert_eq!(before, runtime.capability_table(SENDER_TASK_ID).unwrap());
        }

        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Duplicate,
            original,
            CAPABILITY_RIGHT_SEND,
            0,
        );
        let duplicate = runtime.context(SENDER_TASK_ID).unwrap().rdx;
        assert_eq!(0x11, duplicate);
        assert_eq!(
            2,
            runtime.capability_table(SENDER_TASK_ID).unwrap().live_slots
        );

        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Close,
            original,
            0,
            0,
        );
        assert_eq!(TrapStatus::Ok as u64, runtime.context(1).unwrap().rax);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Send,
            original,
            MESSAGE,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidHandle as u64,
            runtime.context(1).unwrap().rax
        );
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Send,
            duplicate,
            MESSAGE,
            0,
        );
        assert_eq!(TrapStatus::Ok as u64, runtime.context(1).unwrap().rax);
        assert_eq!(MESSAGE, runtime.endpoint().payload);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Close,
            duplicate,
            0,
            0,
        );
        assert_eq!(0, runtime.capability_table(1).unwrap().live_slots);
        assert_eq!(MESSAGE, runtime.endpoint().payload);
    }

    #[test]
    fn task_local_type_rights_and_object_generation_checks_are_exact() {
        let mut receiver = runtime();
        receiver.dispatch_next().unwrap();
        invoke(
            &mut receiver,
            RECEIVER_TASK_ID,
            TrapOperation::Send,
            INITIAL_CAPABILITY_HANDLE,
            7,
            0,
        );
        assert_eq!(
            TrapStatus::RightsDenied as u64,
            receiver.context(RECEIVER_TASK_ID).unwrap().rax
        );
        invoke(
            &mut receiver,
            RECEIVER_TASK_ID,
            TrapOperation::Duplicate,
            INITIAL_CAPABILITY_HANDLE,
            CAPABILITY_RIGHT_RECEIVE,
            0,
        );
        assert_eq!(
            TrapStatus::RightsDenied as u64,
            receiver.context(RECEIVER_TASK_ID).unwrap().rax
        );

        let mut sender = runtime();
        dispatch_sender(&mut sender);
        invoke(
            &mut sender,
            SENDER_TASK_ID,
            TrapOperation::Receive,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        assert_eq!(
            TrapStatus::RightsDenied as u64,
            sender.context(SENDER_TASK_ID).unwrap().rax
        );

        let entry = sender.tasks[0].capabilities.slots[0]
            .entry
            .as_mut()
            .unwrap();
        entry.object_type = OBJECT_TYPE_TASK_CONTROL;
        entry.rights = CAPABILITY_RIGHT_START;
        invoke(
            &mut sender,
            SENDER_TASK_ID,
            TrapOperation::Send,
            INITIAL_CAPABILITY_HANDLE,
            7,
            0,
        );
        assert_eq!(
            TrapStatus::WrongObject as u64,
            sender.context(1).unwrap().rax
        );

        let mut stale_object = runtime();
        dispatch_sender(&mut stale_object);
        stale_object.tasks[0].capabilities.slots[0]
            .entry
            .as_mut()
            .unwrap()
            .object
            .generation += 1;
        let endpoint_before = stale_object.endpoint();
        invoke(
            &mut stale_object,
            SENDER_TASK_ID,
            TrapOperation::Send,
            INITIAL_CAPABILITY_HANDLE,
            7,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidHandle as u64,
            stale_object.context(1).unwrap().rax
        );
        assert_eq!(endpoint_before, stale_object.endpoint());
    }

    #[test]
    fn zero_empty_and_generation_mismatched_handles_preserve_authority_state() {
        let mut runtime = runtime();
        dispatch_sender(&mut runtime);
        for handle in [0, 0x12, 0x20] {
            let table_before = runtime.capability_table(SENDER_TASK_ID).unwrap();
            let endpoint_before = runtime.endpoint();
            invoke(
                &mut runtime,
                SENDER_TASK_ID,
                TrapOperation::Send,
                handle,
                MESSAGE,
                0,
            );
            assert_eq!(
                TrapStatus::InvalidHandle as u64,
                runtime.context(SENDER_TASK_ID).unwrap().rax
            );
            assert_eq!(table_before, runtime.capability_table(1).unwrap());
            assert_eq!(endpoint_before, runtime.endpoint());
        }
        assert_eq!(
            Err(TrapStatus::InvalidHandle),
            runtime.tasks[0].capabilities.resolve(
                RECEIVER_TASK_ID,
                runtime.tasks[0].generation,
                INITIAL_CAPABILITY_HANDLE,
                CAPABILITY_RIGHT_SEND,
            )
        );
    }

    #[test]
    fn peer_table_selector_never_grants_cross_task_authority() {
        let mut runtime = runtime();
        dispatch_sender(&mut runtime);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Duplicate,
            INITIAL_CAPABILITY_HANDLE,
            CAPABILITY_RIGHT_SEND,
            0,
        );
        let sender_only = runtime.context(SENDER_TASK_ID).unwrap().rdx;
        assert_eq!(0x11, sender_only);
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );
        let before = runtime.endpoint();
        invoke(
            &mut runtime,
            RECEIVER_TASK_ID,
            TrapOperation::Receive,
            sender_only,
            0,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidHandle as u64,
            runtime.context(RECEIVER_TASK_ID).unwrap().rax
        );
        assert_eq!(before, runtime.endpoint());
        assert_eq!(
            1,
            runtime
                .capability_table(RECEIVER_TASK_ID)
                .unwrap()
                .live_slots
        );
        assert_eq!(
            2,
            runtime.capability_table(SENDER_TASK_ID).unwrap().live_slots
        );
    }

    #[test]
    fn table_capacity_reuse_stale_and_generation_exhaustion_are_deterministic() {
        let mut table = CapabilityTable::building(1, 11);
        let source = table
            .install_building(CAPABILITY_RIGHT_SEND | CAPABILITY_RIGHT_DUPLICATE)
            .unwrap();
        table.publish().unwrap();
        let mut handles = [0_u64; CAPABILITY_SLOT_COUNT];
        handles[0] = source;
        for item in handles.iter_mut().skip(1) {
            *item = table
                .duplicate(
                    1,
                    11,
                    source,
                    CAPABILITY_RIGHT_SEND | CAPABILITY_RIGHT_DUPLICATE,
                )
                .unwrap();
        }
        assert_eq!(0x1f, handles[15]);
        let full = table;
        assert_eq!(
            Err(TrapStatus::HandleTableFull),
            table.duplicate(1, 11, source, CAPABILITY_RIGHT_SEND)
        );
        assert_eq!(full, table);

        let stale = handles[5];
        table.close(1, 11, stale).unwrap();
        let reused = table
            .duplicate(1, 11, source, CAPABILITY_RIGHT_SEND)
            .unwrap();
        assert_eq!(0x25, reused);
        assert_eq!(
            Err(TrapStatus::InvalidHandle),
            table.resolve(1, 11, stale, CAPABILITY_RIGHT_SEND)
        );

        let entry = table.slots[0].entry.unwrap();
        table.slots[0].generation = CAPABILITY_GENERATION_MAX;
        table
            .close(
                1,
                11,
                CapabilityHandleV1::from_parts(0, CAPABILITY_GENERATION_MAX)
                    .unwrap()
                    .raw(),
            )
            .unwrap();
        assert!(table.slots[0].retired);
        assert_eq!(CAPABILITY_GENERATION_MAX, table.slots[0].generation);
        for slot in table.slots.iter_mut().skip(1) {
            slot.entry = Some(entry);
        }
        let before = table;
        assert_eq!(
            Err(TrapStatus::GenerationExhausted),
            table.duplicate(1, 11, 0x11, CAPABILITY_RIGHT_SEND)
        );
        assert_eq!(before, table);
    }

    #[test]
    fn handle_first_teardown_exposes_the_required_ordered_states() {
        let mut runtime = runtime();
        dispatch_sender(&mut runtime);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::Duplicate,
            INITIAL_CAPABILITY_HANDLE,
            CAPABILITY_RIGHT_SEND,
            0,
        );
        invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Exit, 0, 0, 0);

        let exited = runtime.capability_table(SENDER_TASK_ID).unwrap();
        assert_eq!(CapabilityTableState::Live, exited.state);
        assert_eq!(2, exited.live_slots);
        assert_eq!(SENDER_TASK_ID, runtime.endpoint().sender_task);

        runtime.begin_teardown(SENDER_TASK_ID).unwrap();
        let detached = runtime.capability_table(SENDER_TASK_ID).unwrap();
        assert_eq!(CapabilityTableState::Closing, detached.state);
        assert_eq!(0, detached.live_slots);
        assert_eq!(0, runtime.endpoint().sender_task);
        assert_eq!(Err(RuntimeError::WrongState), runtime.begin_teardown(1));

        // The architecture layer tears the already-detached address space down
        // between these two checked runtime transitions.
        assert_eq!(
            Some(RECEIVER_TASK_ID),
            runtime.complete_teardown(1).unwrap()
        );
        assert_eq!(
            CapabilityTableState::Dead,
            runtime.capability_table(1).unwrap().state
        );
        assert_eq!(0, runtime.capability_table(1).unwrap().task_id);
    }

    #[test]
    fn appended_trap_values_and_reserved_argument_failures_are_stable() {
        assert_eq!(4, TrapOperation::Duplicate as u64);
        assert_eq!(5, TrapOperation::Close as u64);
        assert_eq!(6, TrapOperation::StartWorkload as u64);
        assert_eq!(7, TrapOperation::SubmitApproval as u64);
        assert_eq!(8, TrapOperation::InspectApproval as u64);
        assert_eq!(9, TrapOperation::DecideApproval as u64);
        assert_eq!(10, TrapOperation::CommitEffect as u64);
        assert_eq!(6, TrapStatus::InvalidHandle as u64);
        assert_eq!(7, TrapStatus::WrongObject as u64);
        assert_eq!(8, TrapStatus::RightsDenied as u64);
        assert_eq!(9, TrapStatus::InvalidRights as u64);
        assert_eq!(10, TrapStatus::HandleTableFull as u64);
        assert_eq!(11, TrapStatus::GenerationExhausted as u64);
        assert_eq!(12, TrapStatus::InvalidManifest as u64);
        assert_eq!(13, TrapStatus::InvalidRequest as u64);
        assert_eq!(14, TrapStatus::BrokerFull as u64);
        assert_eq!(15, TrapStatus::ApprovalMismatch as u64);
        assert_eq!(16, TrapStatus::ApprovalDenied as u64);
        assert_eq!(17, TrapStatus::ApprovalExpired as u64);
        assert_eq!(18, TrapStatus::EffectUnavailable as u64);
        assert_eq!(19, TrapStatus::BrokerUnavailable as u64);
        assert_eq!(20, TrapStatus::AlreadyLaunched as u64);

        let mut runtime = runtime();
        dispatch_sender(&mut runtime);
        for (operation, a, b, c) in [
            (
                TrapOperation::Duplicate,
                INITIAL_CAPABILITY_HANDLE,
                CAPABILITY_RIGHT_SEND,
                1,
            ),
            (TrapOperation::Close, INITIAL_CAPABILITY_HANDLE, 1, 0),
            (TrapOperation::Close, INITIAL_CAPABILITY_HANDLE, 0, 1),
        ] {
            let before = runtime.capability_table(1).unwrap();
            invoke(&mut runtime, 1, operation, a, b, c);
            assert_eq!(
                TrapStatus::InvalidOperation as u64,
                runtime.context(1).unwrap().rax
            );
            assert_eq!(before, runtime.capability_table(1).unwrap());
        }
    }

    #[test]
    fn fifo_yield_keeps_unique_membership_and_one_running_task() {
        let mut runtime = runtime();
        assert_eq!(Some(2), runtime.dispatch_next().unwrap());
        install_call(&mut runtime, 2, TrapOperation::Yield as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Switch(1), runtime.handle_trap(2).unwrap());
        assert_eq!(([2, 0], 1), runtime.queue());
        install_call(&mut runtime, 1, TrapOperation::Yield as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Switch(2), runtime.handle_trap(1).unwrap());
        assert_eq!(([1, 0], 1), runtime.queue());
        runtime.validate().unwrap();
    }

    #[test]
    fn reference_block_wake_transfer_and_teardown_is_deterministic() {
        let mut runtime = runtime();
        assert_eq!(Some(2), runtime.dispatch_next().unwrap());
        install_call(
            &mut runtime,
            2,
            TrapOperation::Receive as u64,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        assert_eq!(TrapOutcome::Switch(1), runtime.handle_trap(2).unwrap());
        assert_eq!(TaskState::BlockedReceive, runtime.state(2).unwrap());

        install_call(
            &mut runtime,
            1,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            MESSAGE,
            0,
        );
        assert_eq!(TrapOutcome::Resume(1), runtime.handle_trap(1).unwrap());
        assert_eq!(TaskState::Ready, runtime.state(2).unwrap());
        assert_eq!(TrapStatus::Ok as u64, runtime.context(2).unwrap().rax);
        assert_eq!(MESSAGE, runtime.context(2).unwrap().rdx);
        assert!(!runtime.endpoint().occupied);

        install_call(&mut runtime, 1, TrapOperation::Exit as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Exit(1), runtime.handle_trap(1).unwrap());
        assert_eq!(SENDER_TASK_ID, runtime.endpoint().sender_task);
        assert_eq!(
            CapabilityTableState::Live,
            runtime.capability_table(1).unwrap().state
        );
        runtime.begin_teardown(1).unwrap();
        assert_eq!(0, runtime.endpoint().sender_task);
        assert_eq!(0, runtime.endpoint().sender_generation);
        assert_eq!(
            CapabilityTableState::Closing,
            runtime.capability_table(1).unwrap().state
        );
        assert_eq!(0, runtime.capability_table(1).unwrap().live_slots);
        assert_eq!(Some(2), runtime.complete_teardown(1).unwrap());
        install_call(&mut runtime, 2, TrapOperation::Exit as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Exit(2), runtime.handle_trap(2).unwrap());
        runtime.begin_teardown(2).unwrap();
        assert_eq!(None, runtime.complete_teardown(2).unwrap());
        assert_eq!(TaskState::Dead, runtime.state(1).unwrap());
        assert_eq!(TaskState::Dead, runtime.state(2).unwrap());
        assert_eq!(([0, 0], 0), runtime.queue());
        assert_eq!(
            EndpointSnapshot {
                object_generation: 0,
                sender_task: 0,
                sender_generation: 0,
                receiver_task: 0,
                receiver_generation: 0,
                occupied: false,
                payload: 0,
            },
            runtime.endpoint()
        );
    }

    #[test]
    fn zero_is_data_and_full_send_preserves_first_value() {
        let mut runtime = runtime();
        runtime.queue = RunQueue::new();
        runtime.tasks[0].state = TaskState::Running;
        runtime.tasks[1].state = TaskState::BlockedReceive;
        install_call(
            &mut runtime,
            1,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        assert_eq!(TrapOutcome::Resume(1), runtime.handle_trap(1).unwrap());
        assert_eq!(0, runtime.context(2).unwrap().rdx);
        assert_eq!(TrapStatus::Ok as u64, runtime.context(2).unwrap().rax);

        runtime.endpoint.occupied = true;
        runtime.endpoint.payload = 7;
        install_call(
            &mut runtime,
            1,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            8,
            0,
        );
        assert_eq!(TrapOutcome::Resume(1), runtime.handle_trap(1).unwrap());
        assert_eq!(TrapStatus::SlotFull as u64, runtime.context(1).unwrap().rax);
        assert_eq!(7, runtime.endpoint().payload);
    }

    #[test]
    fn exact_rejections_preserve_scheduler_and_endpoint_state() {
        let calls = [
            (99, 0, 0, 0, TrapStatus::InvalidOperation),
            (
                TrapOperation::Yield as u64,
                1,
                0,
                0,
                TrapStatus::InvalidOperation,
            ),
            (
                TrapOperation::Send as u64,
                9,
                4,
                0,
                TrapStatus::InvalidHandle,
            ),
            (
                TrapOperation::Send as u64,
                INITIAL_CAPABILITY_HANDLE,
                4,
                1,
                TrapStatus::InvalidOperation,
            ),
            (
                TrapOperation::Receive as u64,
                INITIAL_CAPABILITY_HANDLE,
                1,
                0,
                TrapStatus::InvalidOperation,
            ),
            (
                TrapOperation::Exit as u64,
                0,
                1,
                0,
                TrapStatus::InvalidOperation,
            ),
        ];
        for (op, a, b, c, status) in calls {
            let mut runtime = runtime();
            runtime.dispatch_next().unwrap();
            let queue = runtime.queue();
            let endpoint = runtime.endpoint();
            install_call(&mut runtime, 2, op, a, b, c);
            assert_eq!(TrapOutcome::Resume(2), runtime.handle_trap(2).unwrap());
            assert_eq!(status as u64, runtime.context(2).unwrap().rax);
            assert_eq!(queue, runtime.queue());
            assert_eq!(endpoint, runtime.endpoint());
            assert_eq!(TaskState::Running, runtime.state(2).unwrap());
        }
    }

    #[test]
    fn rights_and_peer_exit_contracts_are_exact() {
        let mut runtime = runtime();
        runtime.dispatch_next().unwrap();
        install_call(
            &mut runtime,
            2,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            4,
            0,
        );
        runtime.handle_trap(2).unwrap();
        assert_eq!(
            TrapStatus::RightsDenied as u64,
            runtime.context(2).unwrap().rax
        );

        install_call(&mut runtime, 2, TrapOperation::Exit as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Exit(2), runtime.handle_trap(2).unwrap());
        runtime.begin_teardown(2).unwrap();
        assert_eq!(Some(1), runtime.complete_teardown(2).unwrap());
        install_call(
            &mut runtime,
            1,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            9,
            0,
        );
        runtime.handle_trap(1).unwrap();
        assert_eq!(
            TrapStatus::PeerExited as u64,
            runtime.context(1).unwrap().rax
        );
    }

    #[test]
    fn sender_close_wakes_empty_blocked_receiver_with_peer_exit() {
        let mut runtime = runtime();
        runtime.dispatch_next().unwrap();
        install_call(
            &mut runtime,
            2,
            TrapOperation::Receive as u64,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        assert_eq!(TrapOutcome::Switch(1), runtime.handle_trap(2).unwrap());
        install_call(&mut runtime, 1, TrapOperation::Exit as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Exit(1), runtime.handle_trap(1).unwrap());
        assert_eq!(SENDER_TASK_ID, runtime.endpoint().sender_task);
        runtime.begin_teardown(1).unwrap();
        assert_eq!(
            TrapStatus::PeerExited as u64,
            runtime.context(2).unwrap().rax
        );
        assert_eq!(0, runtime.endpoint().sender_task);
        assert_eq!(0, runtime.endpoint().sender_generation);
        assert_eq!(Some(2), runtime.complete_teardown(1).unwrap());
    }

    #[test]
    fn sender_close_preserves_an_occupied_value_until_receiver_consumes_it() {
        let mut runtime = runtime();
        runtime.dispatch_next().unwrap();
        install_call(&mut runtime, 2, TrapOperation::Yield as u64, 0, 0, 0);
        assert_eq!(TrapOutcome::Switch(1), runtime.handle_trap(2).unwrap());
        install_call(
            &mut runtime,
            1,
            TrapOperation::Send as u64,
            INITIAL_CAPABILITY_HANDLE,
            MESSAGE,
            0,
        );
        runtime.handle_trap(1).unwrap();
        assert!(runtime.endpoint().occupied);

        install_call(&mut runtime, 1, TrapOperation::Exit as u64, 0, 0, 0);
        runtime.handle_trap(1).unwrap();
        assert!(runtime.endpoint().occupied);
        runtime.begin_teardown(1).unwrap();
        assert_eq!(Some(2), runtime.complete_teardown(1).unwrap());
        install_call(
            &mut runtime,
            2,
            TrapOperation::Receive as u64,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        assert_eq!(TrapOutcome::Resume(2), runtime.handle_trap(2).unwrap());
        assert_eq!(MESSAGE, runtime.context(2).unwrap().rdx);
        assert!(!runtime.endpoint().occupied);
    }

    #[test]
    fn receiver_exit_discards_unread_value() {
        let mut runtime = runtime();
        runtime.queue = RunQueue::new();
        runtime.tasks[0].state = TaskState::Ready;
        runtime.queue.push(1).unwrap();
        runtime.tasks[1].state = TaskState::Running;
        runtime.endpoint.occupied = true;
        runtime.endpoint.payload = 0x55;
        install_call(&mut runtime, 2, TrapOperation::Exit as u64, 0, 0, 0);
        runtime.handle_trap(2).unwrap();
        assert_eq!(RECEIVER_TASK_ID, runtime.endpoint().receiver_task);
        runtime.begin_teardown(2).unwrap();
        assert_eq!(0, runtime.endpoint().receiver_task);
        assert_eq!(0, runtime.endpoint().receiver_generation);
        assert!(!runtime.endpoint().occupied);
        assert_eq!(0, runtime.endpoint().payload);
    }

    #[test]
    fn complete_context_layout_and_validation_cover_every_register() {
        let mut frame = TrapFrameV1 {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rbp: 5,
            rsi: 6,
            rdi: 7,
            r8: 8,
            r9: 9,
            r10: 10,
            r11: 11,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,
            rip: TEXT,
            cs: CODE,
            rflags: 0x2,
            rsp: STACK_TOP,
            ss: DATA,
        };
        let policy = ContextPolicy {
            text_start: TEXT,
            text_end: TEXT + 4096,
            stack_start: STACK,
            stack_end: STACK_TOP,
            user_code: CODE,
            user_data: DATA,
        };
        let mut context = TaskContextV1::from_trap(frame, 1, 11, 0x1000);
        assert_eq!((1..=15).collect::<std::vec::Vec<_>>(), context.gprs());
        assert_eq!(Ok(()), context.validate(1, 11, 0x1000, policy));

        frame.rflags = 1 << 9;
        context = TaskContextV1::from_trap(frame, 1, 11, 0x1000);
        assert_eq!(
            Err(ContextError::InvalidFlags),
            context.validate(1, 11, 0x1000, policy)
        );
        context.rflags = 0x2;
        context.generation = 12;
        assert_eq!(
            Err(ContextError::WrongGeneration),
            context.validate(1, 11, 0x1000, policy)
        );
        context.generation = 11;
        context.cs = 0x8;
        assert_eq!(
            Err(ContextError::InvalidSelectors),
            context.validate(1, 11, 0x1000, policy)
        );
        context.cs = CODE;
        context.rip = 0x0000_8000_0000_0000;
        assert_eq!(
            Err(ContextError::InvalidInstructionPointer),
            context.validate(1, 11, 0x1000, policy)
        );
        context.rip = TEXT;
        context.root = 0x2000;
        assert_eq!(
            Err(ContextError::WrongRoot),
            context.validate(1, 11, 0x1000, policy)
        );
        context.root = 0x1000;
        context.rsp = STACK - 8;
        assert_eq!(
            Err(ContextError::InvalidStackPointer),
            context.validate(1, 11, 0x1000, policy)
        );
        context.rsp = STACK_TOP;
        for forbidden in [1 << 10, 3 << 12] {
            context.rflags = 0x2 | forbidden;
            assert_eq!(
                Err(ContextError::InvalidFlags),
                context.validate(1, 11, 0x1000, policy)
            );
        }
    }

    #[test]
    fn bounded_operation_sequences_preserve_all_runtime_invariants() {
        fn walk(runtime: Runtime, depth: usize, seen: &mut std::vec::Vec<Runtime>) {
            if seen.contains(&runtime) || depth == 0 {
                return;
            }
            seen.push(runtime);
            runtime.validate().unwrap();
            let Ok(task) = runtime.running_task() else {
                return;
            };
            let calls = [
                (TrapOperation::Yield as u64, 0, 0, 0),
                (TrapOperation::Send as u64, INITIAL_CAPABILITY_HANDLE, 0, 0),
                (TrapOperation::Send as u64, INITIAL_CAPABILITY_HANDLE, 7, 0),
                (
                    TrapOperation::Receive as u64,
                    INITIAL_CAPABILITY_HANDLE,
                    0,
                    0,
                ),
                (
                    TrapOperation::Duplicate as u64,
                    INITIAL_CAPABILITY_HANDLE,
                    CAPABILITY_RIGHT_SEND,
                    0,
                ),
                (TrapOperation::Close as u64, INITIAL_CAPABILITY_HANDLE, 0, 0),
                (TrapOperation::Exit as u64, 0, 0, 0),
                (99, 0, 0, 0),
            ];
            for (op, a, b, c) in calls {
                let mut next = runtime;
                install_call(&mut next, task, op, a, b, c);
                if let Ok(outcome) = next.handle_trap(task) {
                    if let TrapOutcome::Exit(exited) = outcome {
                        let _ = next.begin_teardown(exited);
                        let _ = next.complete_teardown(exited);
                    }
                    next.validate().unwrap();
                    walk(next, depth - 1, seen);
                }
            }
        }

        let mut initial = runtime();
        initial.dispatch_next().unwrap();
        let mut seen = std::vec::Vec::new();
        walk(initial, 7, &mut seen);
        assert!(seen.len() >= 20);
    }

    #[test]
    fn rejected_internal_transition_restores_every_byte_of_metadata() {
        let mut runtime = runtime();
        let before = runtime;
        assert_eq!(Err(RuntimeError::NoRunningTask), runtime.handle_trap(1));
        assert_eq!(before, runtime);
        assert_eq!(Err(RuntimeError::WrongState), runtime.complete_teardown(1));
        assert_eq!(before, runtime);

        runtime.dispatch_next().unwrap();
        install_call(
            &mut runtime,
            2,
            TrapOperation::Receive as u64,
            INITIAL_CAPABILITY_HANDLE,
            0,
            0,
        );
        runtime.handle_trap(2).unwrap();
        let blocked = runtime;
        assert_eq!(Err(RuntimeError::WrongState), runtime.complete_teardown(2));
        assert_eq!(blocked, runtime);
    }

    #[test]
    fn supervised_layout_manifest_and_runtime_footprint_are_fixed() {
        assert_eq!(32, size_of::<LaunchRouteV1>());
        assert_eq!(184, size_of::<LaunchManifestV1>());
        assert_eq!(56, offset_of!(LaunchManifestV1, routes));
        assert_eq!(80, size_of::<ApprovalRequestV1>());
        assert_eq!(24, offset_of!(ApprovalRequestV1, sequence));
        assert_eq!(56, offset_of!(ApprovalRequestV1, argument));
        assert_eq!(size_of::<Runtime>(), RUNTIME_METADATA_BYTES);
        assert_eq!(3_112, RUNTIME_METADATA_BYTES_V1);
        assert_eq!(Ok(()), REGISTERED_LAUNCH_MANIFEST.validate(5, 1, 16));
    }

    #[test]
    fn manifest_validation_is_default_deny_for_every_fixed_boundary() {
        let cases = [
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.schema_version = 2;
                    value
                },
                ManifestError::InvalidHeader,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.reserved = 1;
                    value
                },
                ManifestError::InvalidHeader,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.manifest_id = 0;
                    value
                },
                ManifestError::InvalidIdentity,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.target_generation += 1;
                    value
                },
                ManifestError::InvalidTarget,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.route_count = 0;
                    value
                },
                ManifestError::MissingRoute,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.route_count = 5;
                    value
                },
                ManifestError::ExcessRoutes,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.routes[0].object_type = 99;
                    value
                },
                ManifestError::InvalidRoute,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.routes[0].rights |= CAPABILITY_RIGHT_DECIDE_APPROVAL;
                    value
                },
                ManifestError::InvalidRoute,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.routes[0].object_generation += 1;
                    value
                },
                ManifestError::InvalidRoute,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.route_count = 2;
                    value.routes[1] = value.routes[0];
                    value
                },
                ManifestError::DuplicateRoute,
            ),
            (
                {
                    let mut value = REGISTERED_LAUNCH_MANIFEST;
                    value.routes[1].reserved = 1;
                    value
                },
                ManifestError::NonzeroUnusedRoute,
            ),
        ];
        for (manifest, error) in cases {
            assert_eq!(Err(error), manifest.validate(5, 1, 16));
        }
        assert_eq!(
            Err(ManifestError::InvalidTarget),
            REGISTERED_LAUNCH_MANIFEST.validate(6, 1, 16)
        );
        assert_eq!(
            Err(ManifestError::InvalidRoute),
            REGISTERED_LAUNCH_MANIFEST.validate(5, 2, 16)
        );
        assert_eq!(
            Err(ManifestError::InsufficientCapacity),
            REGISTERED_LAUNCH_MANIFEST.validate(5, 1, 0)
        );
    }

    #[test]
    fn supervised_publication_is_staged_exact_and_reverses_every_failure() {
        assert_eq!(
            Err(RuntimeError::InvalidGeneration),
            Runtime::new_supervised(context(1, 6, 0x3000), context(2, 5, 0x4000))
        );
        let runtime = supervised_runtime();
        assert_eq!(RuntimeProfile::Supervised, runtime.profile());
        assert_eq!(([1, 0], 1), runtime.queue());
        assert_eq!(TaskState::Ready, runtime.state(1).unwrap());
        assert_eq!(TaskState::Staged, runtime.state(2).unwrap());
        assert_eq!(3, runtime.capability_table(1).unwrap().live_slots);
        assert_eq!(
            CapabilityTableState::Building,
            runtime.capability_table(2).unwrap().state
        );
        assert_eq!(0, runtime.capability_table(2).unwrap().live_slots);
        assert!(!runtime.manifest_publication().published);
        assert_eq!(ApprovalBrokerState::Empty, runtime.approval_broker().state);
        assert_eq!(1, runtime.approval_broker().next_sequence);
        assert_eq!(1, runtime.approval_broker().decision_epoch);
        assert_eq!(
            FIXED_OBJECT_GENERATION,
            runtime.synthetic_effect().object_generation
        );
        runtime.validate().unwrap();

        for step in 0..=4 {
            let mut failed = Runtime::unpublished_supervised(
                context(1, SUPERVISOR_GENERATION, 0x3000),
                context(2, WORKLOAD_GENERATION, 0x4000),
            );
            assert_eq!(
                Err(RuntimeError::PublicationFailure),
                failed.publish_supervisor(Some(step))
            );
            assert_eq!(([0, 0], 0), failed.queue());
            assert_eq!(TaskState::Dead, failed.state(1).unwrap());
            assert_eq!(TaskState::Dead, failed.state(2).unwrap());
            assert_eq!(ApprovalBrokerState::Dead, failed.approval_broker().state);
            assert_eq!(0, failed.synthetic_effect().object_generation);
            failed.validate().unwrap();
        }

        let mut launch = supervised_runtime();
        launch.dispatch_next().unwrap();
        install_call(
            &mut launch,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload as u64,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            MANIFEST_ID,
            0,
        );
        for step in 0..=3 {
            let mut failed = launch;
            let mut expected = launch;
            expected.tasks[0].context.rax = TrapStatus::InvalidManifest as u64;
            expected.tasks[0].context.rdx = 0;
            assert_eq!(
                TrapOutcome::Resume(SENDER_TASK_ID),
                failed
                    .start_workload_with_failure(
                        SENDER_TASK_ID,
                        SUPERVISOR_TASK_CONTROL_HANDLE,
                        MANIFEST_ID,
                        0,
                        Some(step),
                    )
                    .unwrap()
            );
            assert_eq!(expected, failed);
            assert_eq!(TaskState::Staged, failed.state(2).unwrap());
            assert_eq!(0, failed.capability_table(2).unwrap().live_slots);
            failed.validate().unwrap();
        }
    }

    #[test]
    fn only_supervisor_can_publish_the_exact_manifest_once() {
        let mut runtime = supervised_runtime();
        runtime.dispatch_next().unwrap();
        install_call(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload as u64,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            2,
            0,
        );
        let mut expected = runtime;
        expected.tasks[0].context.rax = TrapStatus::InvalidManifest as u64;
        expected.tasks[0].context.rdx = 0;
        assert_eq!(
            TrapOutcome::Resume(SENDER_TASK_ID),
            runtime.handle_trap(SENDER_TASK_ID).unwrap()
        );
        assert_eq!(expected, runtime);
        assert_eq!(TaskState::Staged, runtime.state(2).unwrap());

        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            MANIFEST_ID,
            0,
        );
        assert!(runtime.manifest_publication().published);
        assert_eq!(TaskState::Ready, runtime.state(2).unwrap());
        assert_eq!(([2, 0], 1), runtime.queue());
        assert_eq!(1, runtime.capability_table(2).unwrap().live_slots);

        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            MANIFEST_ID,
            0,
        );
        assert_eq!(
            TrapStatus::AlreadyLaunched as u64,
            runtime.context(1).unwrap().rax
        );
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );
        invoke(
            &mut runtime,
            RECEIVER_TASK_ID,
            TrapOperation::StartWorkload,
            WORKLOAD_APPROVAL_HANDLE,
            MANIFEST_ID,
            0,
        );
        assert_eq!(
            TrapStatus::WrongObject as u64,
            runtime.context(2).unwrap().rax
        );
    }

    #[test]
    fn supervised_handles_enforce_local_type_right_generation_and_reserved_fields() {
        let mut wrong_type = supervised_runtime();
        wrong_type.dispatch_next().unwrap();
        invoke(
            &mut wrong_type,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            1,
            DECISION_DENY,
        );
        assert_eq!(
            TrapStatus::WrongObject as u64,
            wrong_type.context(1).unwrap().rax
        );

        let mut stale = supervised_runtime();
        stale.dispatch_next().unwrap();
        invoke(
            &mut stale,
            SENDER_TASK_ID,
            TrapOperation::Close,
            SUPERVISOR_DECISION_HANDLE,
            0,
            0,
        );
        invoke(
            &mut stale,
            SENDER_TASK_ID,
            TrapOperation::InspectApproval,
            SUPERVISOR_DECISION_HANDLE,
            0,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidHandle as u64,
            stale.context(1).unwrap().rax
        );

        let mut generation = supervised_runtime();
        generation.dispatch_next().unwrap();
        generation.tasks[0].capabilities.slots[0]
            .entry
            .as_mut()
            .unwrap()
            .object
            .generation += 1;
        invoke(
            &mut generation,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            MANIFEST_ID,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidHandle as u64,
            generation.context(1).unwrap().rax
        );

        let mut reserved = supervised_runtime();
        reserved.dispatch_next().unwrap();
        invoke(
            &mut reserved,
            SENDER_TASK_ID,
            TrapOperation::StartWorkload,
            SUPERVISOR_TASK_CONTROL_HANDLE,
            MANIFEST_ID,
            1,
        );
        assert_eq!(
            TrapStatus::InvalidOperation as u64,
            reserved.context(1).unwrap().rax
        );
        invoke(
            &mut reserved,
            SENDER_TASK_ID,
            TrapOperation::InspectApproval,
            SUPERVISOR_DECISION_HANDLE,
            1,
            0,
        );
        assert_eq!(
            TrapStatus::InvalidOperation as u64,
            reserved.context(1).unwrap().rax
        );

        let mut workload = supervised_runtime();
        launch_and_run_workload(&mut workload);
        invoke(
            &mut workload,
            RECEIVER_TASK_ID,
            TrapOperation::DecideApproval,
            WORKLOAD_APPROVAL_HANDLE,
            1,
            DECISION_DENY,
        );
        assert_eq!(
            TrapStatus::RightsDenied as u64,
            workload.context(2).unwrap().rax
        );
        invoke(
            &mut workload,
            RECEIVER_TASK_ID,
            TrapOperation::Duplicate,
            WORKLOAD_APPROVAL_HANDLE,
            CAPABILITY_RIGHT_SUBMIT_APPROVAL,
            0,
        );
        assert_eq!(
            TrapStatus::WrongObject as u64,
            workload.context(2).unwrap().rax
        );
    }

    #[test]
    fn reference_approval_sequence_is_bound_single_use_and_atomic() {
        const FIRST: u64 = 0x31;
        const SECOND: u64 = 0x32;
        const THIRD: u64 = 0x33;
        let mut runtime = supervised_runtime();
        launch_and_run_workload(&mut runtime);

        let first_sequence = submit_and_inspect(&mut runtime, FIRST);
        assert_eq!(1, first_sequence);
        let first_request = runtime.approval_broker().request;
        assert_eq!(PRINCIPAL_ID, first_request.principal_id);
        assert_eq!(RECEIVER_TASK_ID, first_request.workload_task_id);
        assert_eq!(WORKLOAD_GENERATION, first_request.workload_generation);
        assert_eq!(
            APPROVAL_ACTION_ID_COMMIT_SYNTHETIC_VALUE,
            first_request.action_id
        );
        assert_eq!(TEST_EFFECT_OBJECT_ID, first_request.effect_object_id);
        assert_eq!(
            FIXED_OBJECT_GENERATION,
            first_request.effect_object_generation
        );
        assert_eq!(
            CAPABILITY_RIGHT_COMMIT_EFFECT,
            first_request.requested_rights
        );
        assert_eq!(0, first_request.resulting_rights);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            first_sequence,
            DECISION_DENY,
        );
        assert_eq!(TaskState::Ready, runtime.state(2).unwrap());
        assert_eq!(
            TrapStatus::ApprovalDenied as u64,
            runtime.context(2).unwrap().rax
        );
        assert_eq!(ApprovalBrokerState::Empty, runtime.approval_broker().state);
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );

        let second_sequence = submit_and_inspect(&mut runtime, SECOND);
        assert_eq!(2, second_sequence);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            second_sequence,
            DECISION_APPROVE,
        );
        let approved = runtime.approval_broker();
        assert_eq!(ApprovalBrokerState::Approved, approved.state);
        assert_eq!(approved.approval_epoch + 1, approved.expiry_epoch);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            second_sequence,
            DECISION_EXPIRE,
        );
        assert_eq!(
            TrapStatus::ApprovalExpired as u64,
            runtime.context(2).unwrap().rax
        );
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect,
            SUPERVISOR_EFFECT_HANDLE,
            second_sequence,
            SECOND,
        );
        assert_eq!(
            TrapStatus::ApprovalMismatch as u64,
            runtime.context(1).unwrap().rax
        );
        assert!(!runtime.synthetic_effect().occupied);
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );

        let third_sequence = submit_and_inspect(&mut runtime, THIRD);
        assert_eq!(3, third_sequence);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            third_sequence,
            DECISION_APPROVE,
        );
        install_call(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect as u64,
            SUPERVISOR_EFFECT_HANDLE,
            third_sequence,
            THIRD + 1,
        );
        let mut expected = runtime;
        expected.tasks[0].context.rax = TrapStatus::ApprovalMismatch as u64;
        expected.tasks[0].context.rdx = 0;
        runtime.handle_trap(SENDER_TASK_ID).unwrap();
        assert_eq!(expected, runtime);

        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect,
            SUPERVISOR_EFFECT_HANDLE,
            third_sequence,
            THIRD,
        );
        assert_eq!(THIRD, runtime.synthetic_effect().value);
        assert_eq!(TaskState::Ready, runtime.state(2).unwrap());
        assert_eq!(TrapStatus::Ok as u64, runtime.context(2).unwrap().rax);
        assert_eq!(THIRD, runtime.context(2).unwrap().rdx);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect,
            SUPERVISOR_EFFECT_HANDLE,
            third_sequence,
            THIRD,
        );
        assert_eq!(
            TrapStatus::ApprovalMismatch as u64,
            runtime.context(1).unwrap().rax
        );
        runtime.validate().unwrap();
    }

    #[test]
    fn occupied_synthetic_effect_fails_closed_without_consuming_approval() {
        let mut runtime = supervised_runtime();
        launch_and_run_workload(&mut runtime);
        let first_sequence = submit_and_inspect(&mut runtime, 0x41);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            first_sequence,
            DECISION_APPROVE,
        );
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect,
            SUPERVISOR_EFFECT_HANDLE,
            first_sequence,
            0x41,
        );
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );

        let second_sequence = submit_and_inspect(&mut runtime, 0x42);
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            second_sequence,
            DECISION_APPROVE,
        );
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::CommitEffect,
            SUPERVISOR_EFFECT_HANDLE,
            second_sequence,
            0x42,
        );
        assert_eq!(
            TrapStatus::EffectUnavailable as u64,
            runtime.context(1).unwrap().rax
        );
        assert_eq!(0x41, runtime.synthetic_effect().value);
        assert_eq!(
            ApprovalBrokerState::Approved,
            runtime.approval_broker().state
        );
        assert!(runtime.approval_broker().request_present);
        assert_eq!(TaskState::BlockedApproval, runtime.state(2).unwrap());
        invoke(
            &mut runtime,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            second_sequence,
            DECISION_EXPIRE,
        );
        assert_eq!(
            TrapStatus::ApprovalExpired as u64,
            runtime.context(2).unwrap().rax
        );
        runtime.validate().unwrap();
    }

    #[test]
    fn broker_capacity_sequence_and_epoch_exhaustion_fail_closed() {
        let mut full = supervised_runtime();
        launch_and_run_workload(&mut full);
        invoke(
            &mut full,
            RECEIVER_TASK_ID,
            TrapOperation::SubmitApproval,
            WORKLOAD_APPROVAL_HANDLE,
            APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE,
            1,
        );
        assert_eq!(ApprovalBrokerState::Pending, full.approval_broker().state);
        full.submit_approval(
            RECEIVER_TASK_ID,
            WORKLOAD_APPROVAL_HANDLE,
            APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE,
            2,
        )
        .unwrap();
        assert_eq!(TrapStatus::BrokerFull as u64, full.context(2).unwrap().rax);
        assert_eq!(1, full.approval_broker().request.argument);

        let mut sequence = supervised_runtime();
        launch_and_run_workload(&mut sequence);
        sequence.broker.next_sequence = u64::MAX;
        invoke(
            &mut sequence,
            RECEIVER_TASK_ID,
            TrapOperation::SubmitApproval,
            WORKLOAD_APPROVAL_HANDLE,
            APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE,
            7,
        );
        assert_eq!(u64::MAX, sequence.approval_broker().request.sequence);
        assert!(sequence.approval_broker().sequence_exhausted);
        invoke(
            &mut sequence,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            u64::MAX,
            DECISION_DENY,
        );
        invoke(&mut sequence, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0);
        invoke(
            &mut sequence,
            RECEIVER_TASK_ID,
            TrapOperation::SubmitApproval,
            WORKLOAD_APPROVAL_HANDLE,
            APPROVAL_REQUEST_KIND_COMMIT_SYNTHETIC_VALUE,
            8,
        );
        assert_eq!(
            TrapStatus::BrokerUnavailable as u64,
            sequence.context(2).unwrap().rax
        );
        assert_eq!(u64::MAX, sequence.approval_broker().next_sequence);

        let mut epoch = supervised_runtime();
        launch_and_run_workload(&mut epoch);
        let pending = submit_and_inspect(&mut epoch, 9);
        epoch.broker.decision_epoch = u64::MAX;
        invoke(
            &mut epoch,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            pending,
            DECISION_DENY,
        );
        assert_eq!(
            TrapStatus::BrokerUnavailable as u64,
            epoch.context(1).unwrap().rax
        );
        assert_eq!(
            TrapStatus::BrokerUnavailable as u64,
            epoch.context(2).unwrap().rax
        );
        assert_eq!(ApprovalBrokerState::Closing, epoch.approval_broker().state);
        assert_eq!(TaskState::Ready, epoch.state(2).unwrap());
        assert_eq!(
            TrapOutcome::Switch(RECEIVER_TASK_ID),
            invoke(&mut epoch, SENDER_TASK_ID, TrapOperation::Yield, 0, 0, 0)
        );
        invoke(&mut epoch, RECEIVER_TASK_ID, TrapOperation::Exit, 0, 0, 0);
        epoch.begin_teardown(RECEIVER_TASK_ID).unwrap();
        assert_eq!(ApprovalBrokerState::Closing, epoch.approval_broker().state);
    }

    #[test]
    fn approval_references_are_removed_before_handles_and_final_state_is_empty() {
        let mut runtime = supervised_runtime();
        launch_and_run_workload(&mut runtime);
        submit_and_inspect(&mut runtime, 0x77);
        invoke(&mut runtime, SENDER_TASK_ID, TrapOperation::Exit, 0, 0, 0);
        runtime.begin_teardown(SENDER_TASK_ID).unwrap();
        assert_eq!(
            ApprovalBrokerState::Closing,
            runtime.approval_broker().state
        );
        assert!(!runtime.approval_broker().request_present);
        assert_eq!(0, runtime.approval_broker().supervisor_task_id);
        assert_eq!(0, runtime.synthetic_effect().object_generation);
        assert_eq!(
            CapabilityTableState::Closing,
            runtime.capability_table(1).unwrap().state
        );
        assert_eq!(0, runtime.capability_table(1).unwrap().live_slots);
        assert_eq!(
            TrapStatus::ApprovalDenied as u64,
            runtime.context(2).unwrap().rax
        );
        assert_eq!(
            Some(RECEIVER_TASK_ID),
            runtime.complete_teardown(1).unwrap()
        );

        invoke(&mut runtime, RECEIVER_TASK_ID, TrapOperation::Exit, 0, 0, 0);
        runtime.begin_teardown(RECEIVER_TASK_ID).unwrap();
        assert!(!runtime.manifest_publication().published);
        assert_eq!(0, runtime.capability_table(2).unwrap().live_slots);
        assert_eq!(None, runtime.complete_teardown(2).unwrap());
        assert_eq!(ApprovalBrokerState::Dead, runtime.approval_broker().state);
        assert_eq!(0, runtime.synthetic_effect().object_generation);
        assert_eq!(([0, 0], 0), runtime.queue());
        runtime.validate().unwrap();

        let mut approved = supervised_runtime();
        launch_and_run_workload(&mut approved);
        let sequence = submit_and_inspect(&mut approved, 0x78);
        invoke(
            &mut approved,
            SENDER_TASK_ID,
            TrapOperation::DecideApproval,
            SUPERVISOR_DECISION_HANDLE,
            sequence,
            DECISION_APPROVE,
        );
        invoke(&mut approved, SENDER_TASK_ID, TrapOperation::Exit, 0, 0, 0);
        approved.begin_teardown(SENDER_TASK_ID).unwrap();
        assert_eq!(
            TrapStatus::ApprovalExpired as u64,
            approved.context(2).unwrap().rax
        );
        assert!(!approved.approval_broker().request_present);
        assert_eq!(0, approved.synthetic_effect().object_generation);
        assert_eq!(0, approved.capability_table(1).unwrap().live_slots);
        approved.validate().unwrap();
    }
}
