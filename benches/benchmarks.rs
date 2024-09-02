use acctblty::{
    accountability_server::{AccServerParams, AccountabilityServer}, sender::{Sender, SenderChannel}, sender_tag::{ReportTag, SenderTag}, tag::{EncSenderId, Tag, TagSignature}, tag_verifier, utils::{basepoint_order, random_point, random_scalar}
};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::Scalar;
use rand::{rngs::OsRng, RngCore};

fn get_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threshold: 10,
            epoch_duration: 24,
            epoch_start: 1614556800, // March 1, 2021 00:00:00
            tag_duration: 2,
            compute_reputation: None,
            noise_distribution: None,
            max_vks_per_epoch: 100,
        },
        &mut rng,
    );
    let mut sender = Sender::new("sender1", &mut rng);
    let _ = server.set_sender_epk(&sender.epk, &sender.handle);

    let receiver_addr = "receiver_addr";
    let channel = sender.add_channel(receiver_addr, &mut rng);

    c.bench_function("get_tag", |b| {
        b.iter(|| {
            let result = sender.get_tag(&channel, &mut server, &mut rng);
            assert!(result.is_ok());
        })
    });
}

fn issue_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threshold: 10,
            epoch_duration: 24,
            epoch_start: 1614556800, // March 1, 2021 00:00:00
            tag_duration: 2,
            compute_reputation: None,
            noise_distribution: None,
            max_vks_per_epoch: 100,
        },
        &mut rng,
    );

    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);

    let sender_handle = "sender_handle";
    let sender = Sender::new(sender_handle, &mut rng);
    let _ = server.set_sender_epk(&sender.epk, &sender.handle);

    c.bench_function("issue_tag", |b| {
        b.iter(|| {
            let result = server.issue_tag(&commitment_hr.to_vec(), &commitment_vks.to_vec(), sender_handle, &mut rng);
            assert!(result.is_ok());
        })
    });
}

fn verify_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threshold: 10,
            epoch_duration: 24,
            epoch_start: 1614556800, // March 1, 2021 00:00:00
            tag_duration: 2,
            compute_reputation: None,
            noise_distribution: None,
            max_vks_per_epoch: 100,
        },
        &mut rng,
    );
    let mut sender = Sender::new("sender1", &mut rng);
    let _ = server.set_sender_epk(&sender.epk, &sender.handle);

    let receiver_addr = "receiver_addr";
    let channel = sender.add_channel(receiver_addr, &mut rng);

    let tag = sender
        .get_tag(&channel, &mut server, &mut rng)
        .unwrap();

    c.bench_function("verify_tag", |b| {
        b.iter(|| {
            let _ = tag_verifier::verify(
                receiver_addr,
                &tag,
                &server.get_verifying_key(),
            );
        })
    });
}

fn report_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threshold: 10,
            epoch_duration: 24,
            epoch_start: 1614556800, // March 1, 2021 00:00:00
            tag_duration: 2,
            compute_reputation: None,
            noise_distribution: None,
            max_vks_per_epoch: 100,
        },
        &mut rng,
    );

    const NUM_SENDERS: usize = 1000000;

    // Initialize NUM_SENDERS senders
    let mut senders: Vec<Sender> = Vec::new();
    for i in 0..NUM_SENDERS {
        let sender_handle = format!("sender{}", i);
        let sender = Sender::new(&sender_handle, &mut rng);
        let _ = server.set_sender_epk(&sender.epk, &sender.handle);
        senders.push(sender);
    }

    let receiver_addr = "receiver_addr";
    let channels: Vec<SenderChannel> = (0..NUM_SENDERS).map(|i| senders[i].add_channel(receiver_addr, &mut rng)).collect();

    // Get NUM_SENDERS tags
    let mut tags: Vec<SenderTag> = Vec::new();
    for idx in 0..NUM_SENDERS {
        tags.push(
            senders[idx]
                .get_tag(&channels[idx], &mut server, &mut rng)
                .unwrap(),
        );
    }

    let mut idx = 0;

    c.bench_function("report_tag", |b| {
        b.iter(|| {
            let tag = tags.get(idx as usize).unwrap();
            let result = server.report(&tag.report_tag);
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

fn serialize_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut signature: [u8; 64] = [0; 64];
    rng.fill_bytes(&mut signature);
    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);
    let mut enc_sender_id = [0u8; 48];
    rng.fill_bytes(&mut enc_sender_id);


    let tag = Tag {
        commitment_hr: commitment_hr,
        commitment_vks: commitment_vks,
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: EncSenderId(enc_sender_id),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: TagSignature(signature),
    };

    c.bench_function("serialize_tag", |b| {
        b.iter(|| {
            let vec = tag.to_vec();
            assert_eq!(vec.len(), 304);
        });
    });
}

fn deserialize_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut signature: [u8; 64] = [0; 64];
    rng.fill_bytes(&mut signature);
    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);
    let mut enc_sender_id = [0u8; 48];
    rng.fill_bytes(&mut enc_sender_id);

    let tag = Tag {
        commitment_hr: commitment_hr,
        commitment_vks: commitment_vks,
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: EncSenderId(enc_sender_id),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: TagSignature(signature),
    };

    let vec = tag.to_vec();

    c.bench_function("deserialize_tag", |b| {
        b.iter(|| {
            let result = Tag::from_slice(&vec);
            assert!(result.is_ok());
        });
    });
}

fn serialize_full_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut signature: [u8; 64] = [0; 64];
    rng.fill_bytes(&mut signature);
    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);
    let mut enc_sender_id = [0u8; 48];
    rng.fill_bytes(&mut enc_sender_id);
    let mut randomness_hr = [0u8; 32];
    rng.fill_bytes(&mut randomness_hr);
    let mut randomness_vks = [0u8; 32];
    rng.fill_bytes(&mut randomness_vks);
    let proof = (random_scalar(&mut rng), random_scalar(&mut rng));    

    let tag = Tag {
        commitment_hr: commitment_hr,
        commitment_vks: commitment_vks,
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: EncSenderId(enc_sender_id),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: TagSignature(signature),
    };

    let report_tag = ReportTag {
        tag,
        proof: proof,
        r_big: random_point(&mut rng),
    };
    
    let sender_tag = SenderTag {
        report_tag,
        randomness_hr: randomness_hr,
        randomness_vks: randomness_vks,
        vks: random_point(&mut rng),
    };

    c.bench_function("serialize_full_tag", |b| {
        b.iter(|| {
            let vec = sender_tag.to_vec();
            assert_eq!(vec.len(), 508);
        });
    });
}

fn deserialize_full_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut signature: [u8; 64] = [0; 64];
    rng.fill_bytes(&mut signature);
    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);
    let mut enc_sender_id = [0u8; 48];
    rng.fill_bytes(&mut enc_sender_id);
    let mut randomness_hr = [0u8; 32];
    rng.fill_bytes(&mut randomness_hr);
    let mut randomness_vks = [0u8; 32];
    rng.fill_bytes(&mut randomness_vks);
    let proof = (random_scalar(&mut rng), random_scalar(&mut rng));    

    let tag = Tag {
        commitment_hr: commitment_hr,
        commitment_vks: commitment_vks,
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: EncSenderId(enc_sender_id),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: TagSignature(signature),
    };

    let report_tag = ReportTag {
        tag,
        proof: proof,
        r_big: random_point(&mut rng),
    };

    let sender_tag = SenderTag {
        report_tag,
        randomness_hr: randomness_hr,
        randomness_vks: randomness_vks,
        vks: random_point(&mut rng),
    };

    let vec = sender_tag.to_vec();

    c.bench_function("deserialize_full_tag", |b| {
        b.iter(|| {
            let result = SenderTag::from_slice(&vec);
            assert!(result.is_ok());
        });
    });
}

fn end_to_end_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threshold: 10,
            epoch_duration: 24,
            epoch_start: 1614556800, // March 1, 2021 00:00:00
            tag_duration: 2,
            compute_reputation: None,
            noise_distribution: None,
            max_vks_per_epoch: 100,
        },
        &mut rng,
    );
    let mut sender = Sender::new("sender1", &mut rng);
    let _ = server.set_sender_epk(&sender.epk, &sender.handle);
    let verifying_key = server.get_verifying_key();

    let receiver_addr = "receiver_addr";
    let channel = sender.add_channel(receiver_addr, &mut rng);

    c.bench_function("end_to_end", |b| {
        b.iter(|| {
            let tag = sender
                .get_tag(&channel, &mut server, &mut rng)
                .unwrap();
            let _ = tag_verifier::verify(
                receiver_addr,
                &tag,
                &verifying_key,
            );
            let _ = server.report(&tag.report_tag);
            server.update_scores(&mut rng);
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
    serialize_tag_bench,
    deserialize_tag_bench,
    serialize_full_tag_bench,
    deserialize_full_tag_bench,
    end_to_end_bench
);

criterion_main!(benches);
