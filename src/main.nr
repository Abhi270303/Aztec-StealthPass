use dep::aztec::macros::aztec;

#[aztec]
pub contract StealthPass {
    use dep::aztec::{
        encrypted_logs::log_assembly_strategies::default_aes128::note::encode_and_encrypt_note,
        macros::{
            events::event,
            functions::{initializer, internal, private, public},
            storage::storage,
        },
        prelude::{AztecAddress, PrivateSet, PublicImmutable},
        protocol_types::traits::Serialize,
        unencrypted_logs::unencrypted_event_emission::encode_event,
        utils::comparison::Comparator,
    };
    use dep::uint_note::uint_note::UintNote;
    use router::utils::privately_check_timestamp;
    use token::Token;
    use std::meta::derive;

    #[derive(Serialize)]
    #[event]
    struct TicketPurchased {
        buyer: AztecAddress,
        event_id: U128,
        amount: U128,
    }

    #[derive(Serialize)]
    #[event]
    struct WithdrawalProcessed {
        event_owner: AztecAddress,
        amount: U128,
    }

    #[storage]
    struct Storage<Context> {
        native_token: PublicImmutable<AztecAddress, Context>,
        event_owner: PublicImmutable<AztecAddress, Context>,
        event_deadline: PublicImmutable<u64, Context>,
        ticket_price: PublicImmutable<U128, Context>,
        purchased_tickets: PrivateSet<UintNote, Context>,
    }

    #[public]
    #[initializer]
    fn init(native_token: AztecAddress, event_owner: AztecAddress, event_deadline: u64, ticket_price: U128) {
        storage.native_token.initialize(native_token);
        storage.event_owner.initialize(event_owner);
        storage.event_deadline.initialize(event_deadline);
        storage.ticket_price.initialize(ticket_price);
    }

    #[private]
    fn buy_ticket() {
        let deadline = storage.event_deadline.read();
        privately_check_timestamp(Comparator.LT, deadline, &mut context);
        
        let buyer = context.msg_sender();
        let price = storage.ticket_price.read();
        
        Token::at(storage.native_token.read())
            .transfer_in_private(buyer, context.this_address(), price, 0)
            .call(&mut context);
        
        let mut note = UintNote::new(price, buyer);
        storage.purchased_tickets.insert(&mut note).emit(encode_and_encrypt_note(
            &mut context, buyer, buyer,
        ));
    }

    #[private]
    fn withdraw_funds(amount: U128) {
        let owner = storage.event_owner.read();
        assert(context.msg_sender() == owner, "Not the event owner");
        
        Token::at(storage.native_token.read()).transfer(owner, amount).call(&mut context);
        
        StealthPass::at(context.this_address())
            ._publish_withdrawal_receipt(amount, owner)
            .enqueue(&mut context);
    }

    #[public]
    #[internal]
    fn _publish_withdrawal_receipt(amount: U128, owner: AztecAddress) {
        WithdrawalProcessed { amount, event_owner: owner }.emit(encode_event(&mut context));
    }
}
