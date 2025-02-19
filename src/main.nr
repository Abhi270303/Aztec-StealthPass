use dep::aztec::{
    keys::getters::{get_nsk_app, get_public_keys},
    macros::notes::note,
    note::utils::compute_note_hash_for_nullify,
    protocol_types::{
        address::AztecAddress,
        constants::GENERATOR_INDEX__NOTE_NULLIFIER,
        hash::poseidon2_hash_with_separator,
        traits::{Packable, Serialize},
    },
};
use dep::aztec::prelude::{NoteHeader, NullifiableNote, PrivateContext};

// --- Event Struct ---
pub struct Event {
    owner: AztecAddress,
    price: u64,     // Ticket price in USD (converted to crypto)
    total_sold: u32, // Track ticket sales
    is_completed: bool, // Mark event as completed
}

// --- Ticket Note ---
#[note]
pub struct TicketNote {
    event_id: u32,
    ticket_id: u32,
    owner: AztecAddress,
    randomness: Field,
}

// --- Implement Ticket Methods ---
impl TicketNote {
    pub fn new(event_id: u32, ticket_id: u32, owner: AztecAddress, randomness: Field) -> Self {
        TicketNote {
            event_id,
            ticket_id,
            owner,
            randomness,
            header: NoteHeader::empty(),
        }
    }
}

// --- Nullify Ticket After Use ---
impl NullifiableNote for TicketNote {
    fn compute_nullifier(self, context: &mut PrivateContext, note_hash_for_nullify: Field) -> Field {
        let owner_npk_m_hash: Field = get_public_keys(self.owner).npk_m.hash();
        let secret = context.request_nsk_app(owner_npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field,
        )
    }

    unconstrained fn compute_nullifier_without_context(self, storage_slot: Field) -> Field {
        let note_hash_for_nullify = compute_note_hash_for_nullify(self, storage_slot);
        let owner_npk_m_hash: Field = get_public_keys(self.owner).npk_m.hash();
        let secret = get_nsk_app(owner_npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER as Field,
        )
    }
}

// --- Serialize Ticket for Storage ---
impl Serialize<4> for TicketNote {
    fn serialize(self) -> [Field; 4] {
        [
            self.event_id.to_field(),
            self.ticket_id.to_field(),
            self.owner.to_field(),
            self.randomness,
        ]
    }
}

// --- Smart Contract for StealthPass ---
pub struct StealthPass;

impl StealthPass {
    // --- Create an Event ---
    pub fn create_event(context: &mut PrivateContext, event_id: u32, price: u64) -> Event {
        let owner = context.sender();
        Event {
            owner,
            price,
            total_sold: 0,
            is_completed: false,
        }
    }

    // --- Purchase Ticket Privately ---
    pub fn buy_ticket(context: &mut PrivateContext, event: &mut Event) -> TicketNote {
        let buyer = context.sender();
        let ticket_id = event.total_sold + 1;
        let randomness = context.generate_randomness();

        // Ensure payment is correct
        context.pay_private(event.owner, event.price);

        // Create a private ticket note
        let ticket = TicketNote::new(event_id, ticket_id, buyer, randomness);
        context.emit_private_note(ticket.clone());

        // Increase total ticket count
        event.total_sold += 1;

        ticket
    }

    // --- Verify & Nullify Ticket (On Event Day) ---
    pub fn use_ticket(context: &mut PrivateContext, ticket: TicketNote) {
        let ticket_hash = compute_note_hash_for_nullify(ticket, context.storage_slot());
        let nullifier = ticket.compute_nullifier(context, ticket_hash);

        // Ensure this ticket has NOT been used before
        context.record_nullifier(nullifier);

        // Emit event that ticket is used
        context.emit_event("TicketUsed", ticket.event_id.to_field(), ticket.ticket_id.to_field());
    }

    // --- Withdraw Funds (After Event Ends) ---
    pub fn withdraw_funds(context: &mut PrivateContext, event: &mut Event) {
        assert!(event.is_completed, "Event is not yet completed");

        let owner = context.sender();
        assert!(owner == event.owner, "Only event owner can withdraw");

        // Transfer funds to event owner
        context.withdraw_private(owner);

        // Mark event as finalized
        event.is_completed = true;
    }
}
