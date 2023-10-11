use acctblty::{accountability_server::AccountabilityServer, sender::Sender, tag_verifier, tag::Tag};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, RngCore};

fn get_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let server = AccountabilityServer::new(&mut rng);
    let sender = Sender::new("sender1");

    let message = "This is a test message";
    let receiver_handle = "receiver_handle";

    c.bench_function("get_tag", |b| {
        b.iter(|| sender.get_tag(&message, &receiver_handle, &server, &mut rng))
    });
}

fn issue_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let server = AccountabilityServer::new(&mut rng);

    let mut commitment = [0u8; 32];
    rng.fill_bytes(&mut commitment);

    let sender_handle = "sender_handle";
    let tag_duration = 24;

    c.bench_function("issue_tag", |b| {
        b.iter(|| server.issue_tag(&commitment.to_vec(), sender_handle, tag_duration))
    });
}

fn verify_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let server = AccountabilityServer::new(&mut rng);
    let sender = Sender::new("sender1");
    let verifying_key = server.get_verifying_key();

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    let tag = sender.get_tag(msg, receiver_handle, &server, &mut rng);

    c.bench_function("verify_tag", |b| {
        b.iter(|| {
            let _ = tag_verifier::verify(receiver_handle, msg, &tag.0, &tag.1, &verifying_key);
        })
    });
}

fn report_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let server = AccountabilityServer::new(&mut rng);

    const NUM_SENDERS: usize = 1000000;

    // Initialize NUM_SENDERS senders
    let mut senders: Vec<Sender> = Vec::new();
    for i in 0..NUM_SENDERS {
        let sender_handle = format!("sender{}", i);
        senders.push(Sender::new(&sender_handle));
    }

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    // Get NUM_SENDERS tags
    let mut tags: Vec<(Tag, Vec<u8>)> = Vec::new();
    for idx in 0..NUM_SENDERS {
        tags.push(senders[idx].get_tag(msg, receiver_handle, &server, &mut rng));
    }

    let mut idx = 0;

    c.bench_function("report_tag", |b| {
        b.iter(|| {
            let result = server.report(&tags[idx as usize].0);
            assert!(result.is_ok());
            idx = idx + 1;
            assert!(idx < NUM_SENDERS);
        })
    });
}

fn end_to_end_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let server = AccountabilityServer::new(&mut rng);
    let sender = Sender::new("sender1");
    let verifying_key = server.get_verifying_key();

    let receiver_handle = "receiver_handle";
    let msg = "This is a test message";

    c.bench_function("end_to_end", |b| {
        b.iter(|| {
            let tag = sender.get_tag(msg, receiver_handle, &server, &mut rng);
            let _ = tag_verifier::verify(receiver_handle, msg, &tag.0, &tag.1, &verifying_key);
            let _ = server.report(&tag.0);
        })
    });
}

criterion_group!(
    benches,
    get_tag_bench,
    issue_tag_bench,
    verify_tag_bench,
    report_tag_bench,
    end_to_end_bench
);

criterion_main!(benches);
