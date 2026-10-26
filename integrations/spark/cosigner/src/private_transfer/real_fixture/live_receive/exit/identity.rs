//! Message-bound threshold ECDSA tickets, including native challenges.
use super::*;
pub(super) fn presign(
    engine: &Engine,
    wallet: &mut JointIdentityJournal,
    digest: [u8; 32],
) -> Result<()> {
    let request = match wallet.pending_presign_request()? {
        Some(request) => {
            ensure!(
                matches!(request.command, Command::IdentityPrepare {message:Some(message),..} if message == digest),
                "pending identity ticket belongs to another message; retain it for its original operation"
            );
            request
        }
        None => wallet.prepare_message_request(digest)?,
    };
    let id = request.intent.operation;
    let response = engine.handle(&request)?;
    let initial = engine.identity_initial_frame(&request)?;
    wallet.bind_prepare(&id, &response, &initial)?;
    while !wallet.presign_rounds_complete(&id)? {
        let (request, frame) = wallet.next_request(&id)?;
        let (response, reply) = engine.handle_identity_frame(&request, &frame)?;
        wallet.bind_reply(
            &id,
            &request,
            &response,
            &reply.context("native identity presign aborted")?,
        )?;
    }
    wallet.finish_presign(&id)
}
pub(super) fn sign(
    engine: &Engine,
    wallet: &mut JointIdentityJournal,
    digest: [u8; 32],
) -> Result<Vec<u8>> {
    if let Some(signature) = wallet.saved_signature(&digest)? {
        return Ok(signature);
    }
    let request = if let Some(request) = wallet.saved_sign_request(&digest)? {
        request
    } else {
        match wallet.sign_request(digest) {
            Ok(request) => request,
            Err(_) => {
                presign(engine, wallet, digest)?;
                wallet.sign_request(digest)?
            }
        }
    };
    let response = engine.handle(&request)?;
    ensure!(
        engine.handle(&request)? == response,
        "native identity exact replay changed"
    );
    wallet.complete_signature(&request, &response)
}
