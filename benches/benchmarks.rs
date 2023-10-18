use acctblty::{
    accountability_server::AccountabilityServer,
    sender::Sender,
    tag::Tag,
    tag_verifier,
    utils::{basepoint_order, random_point, random_scalar},
};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{rngs::OsRng, RngCore};

fn get_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(100, 10, &mut rng);
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);

    let message = "This is a test message";
    let receiver_handle = "receiver_handle";

    c.bench_function("get_tag", |b| {
        b.iter(|| {
            let result = sender.get_tag(&message, &receiver_handle, &server, &mut rng);
            assert!(result.is_ok());
        })
    });
}

fn issue_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(100, 10, &mut rng);

    let mut commitment = [0u8; 32];
    rng.fill_bytes(&mut commitment);

    let sender_handle = "sender_handle";
    let tag_duration = 24;
    let sender = Sender::new(sender_handle, &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);

    c.bench_function("issue_tag", |b| {
        b.iter(|| {
            let result =
                server.issue_tag(&commitment.to_vec(), sender_handle, tag_duration, &mut rng);
            assert!(result.is_ok());
        })
    });
}

fn verify_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(100, 10, &mut rng);
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);
    let verifying_key = server.get_verifying_key();

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    let tag = sender
        .get_tag(msg, receiver_handle, &server, &mut rng)
        .unwrap();

    c.bench_function("verify_tag", |b| {
        b.iter(|| {
            let _ = tag_verifier::verify(
                receiver_handle,
                msg,
                &tag.0,
                &tag.1,
                &tag.2,
                &tag.3,
                &verifying_key,
            );
        })
    });
}

fn report_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(100, 10, &mut rng);

    const NUM_SENDERS: usize = 1000000;

    // Initialize NUM_SENDERS senders
    let mut senders: Vec<Sender> = Vec::new();
    for i in 0..NUM_SENDERS {
        let sender_handle = format!("sender{}", i);
        let sender = Sender::new(&sender_handle, &mut rng);
        server.set_sender_pk(&sender.epk, &sender.handle);
        senders.push(sender);
    }

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    // Get NUM_SENDERS tags
    let mut tags: Vec<(Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint)> = Vec::new();
    for idx in 0..NUM_SENDERS {
        tags.push(
            senders[idx]
                .get_tag(msg, receiver_handle, &server, &mut rng)
                .unwrap(),
        );
    }

    let mut idx = 0;

    c.bench_function("report_tag", |b| {
        b.iter(|| {
            let tag = tags.get(idx as usize).unwrap();
            let result = server.report(tag.0.clone(), tag.2, tag.3);
            assert!(result.is_ok());
            idx = idx + 1;
            assert!(idx < NUM_SENDERS);
        })
    });
}

fn generate_nizqdleq_proof_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let esk = random_scalar(&mut rng);
    let basepoint_order = basepoint_order();
    let x_big = random_point(&mut rng);
    let y_big = esk * x_big;
    let q_big = random_point(&mut rng);
    let r_big = esk * q_big;

    c.bench_function("generate_nizqdleq_proof", |b| {
        b.iter(|| {
            let proof = acctblty::nizqdleq::prove(
                &basepoint_order,
                &x_big,
                &y_big,
                &q_big,
                &r_big,
                &esk,
                &mut rng,
            );
            assert!(proof.0 != Scalar::ONE);
            assert!(proof.1 != Scalar::ONE);
        });
    });
}

fn verify_nizqdleq_proof_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let esk = random_scalar(&mut rng);
    let basepoint_order = basepoint_order();
    let x_big = random_point(&mut rng);
    let y_big = esk * x_big;
    let q_big = random_point(&mut rng);
    let r_big = esk * q_big;
    let proof = acctblty::nizqdleq::prove(
        &basepoint_order,
        &x_big,
        &y_big,
        &q_big,
        &r_big,
        &esk,
        &mut rng,
    );

    c.bench_function("verify_nizqdleq_proof", |b| {
        b.iter(|| {
            let result = acctblty::nizqdleq::verify(
                &basepoint_order,
                &x_big,
                &y_big,
                &q_big,
                &r_big,
                &proof,
            );
            assert!(result);
        });
    });
}

fn end_to_end_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(100, 10, &mut rng);
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);
    let verifying_key = server.get_verifying_key();

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    c.bench_function("end_to_end", |b| {
        b.iter(|| {
            let tag = sender
                .get_tag(msg, receiver_handle, &server, &mut rng)
                .unwrap();
            let _ = tag_verifier::verify(
                receiver_handle,
                msg,
                &tag.0,
                &tag.1,
                &tag.2,
                &tag.3,
                &verifying_key,
            );
            let _ = server.report(tag.0, tag.2, tag.3);
            server.update_scores();
        })
    });
}

criterion_group!(
    benches,
    get_tag_bench,
    issue_tag_bench,
    verify_tag_bench,
    generate_nizqdleq_proof_bench,
    verify_nizqdleq_proof_bench,
    report_tag_bench,
    end_to_end_bench
);

criterion_main!(benches);
