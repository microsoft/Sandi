use acctblty::{
    accountability_server::{AccServerParams, AccountabilityServer},
    sender::Sender,
    sender_tag::SenderTag,
    tag_verifier,
    utils::{basepoint_order, random_point, random_scalar}, tag::Tag,
};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::Scalar;
use rand::{rngs::OsRng, RngCore};

fn get_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: None,
        },
        &mut rng,
    );
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);

    let receiver_handle = "receiver_handle";

    c.bench_function("get_tag", |b| {
        b.iter(|| {
            let result = sender.get_tag(&receiver_handle, &server, &mut rng);
            assert!(result.is_ok());
        })
    });
}

fn issue_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: None,
        },
        &mut rng,
    );

    let mut commitment_hr = [0u8; 32];
    rng.fill_bytes(&mut commitment_hr);
    let mut commitment_vks = [0u8; 32];
    rng.fill_bytes(&mut commitment_vks);

    let sender_handle = "sender_handle";
    let sender = Sender::new(sender_handle, &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);

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
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: None,
        },
        &mut rng,
    );
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);
    let verifying_key = server.get_verifying_key();

    let receiver_handle = "receiver_handle";

    let tag = sender
        .get_tag(receiver_handle, &server, &mut rng)
        .unwrap();

    c.bench_function("verify_tag", |b| {
        b.iter(|| {
            let _ = tag_verifier::verify(
                receiver_handle,
                sender.get_verifying_key(),
                &tag.tag,
                &tag.randomness_hr,
                &tag.randomness_vks,
                &tag.proof,
                &tag.r_big,
                &verifying_key,
            );
        })
    });
}

fn report_tag_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: None,
        },
        &mut rng,
    );

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

    // Get NUM_SENDERS tags
    let mut tags: Vec<SenderTag> = Vec::new();
    for idx in 0..NUM_SENDERS {
        tags.push(
            senders[idx]
                .get_tag(receiver_handle, &server, &mut rng)
                .unwrap(),
        );
    }

    let mut idx = 0;

    c.bench_function("report_tag", |b| {
        b.iter(|| {
            let tag = tags.get(idx as usize).unwrap();
            let result = server.report(tag.tag.clone(), tag.proof, tag.r_big);
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
        commitment_hr: commitment_hr.to_vec(),
        commitment_vks: commitment_vks.to_vec(),
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: enc_sender_id.to_vec(),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: signature.to_vec(),
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
        commitment_hr: commitment_hr.to_vec(),
        commitment_vks: commitment_vks.to_vec(),
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: enc_sender_id.to_vec(),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: signature.to_vec(),
    };

    let vec = tag.to_vec();

    c.bench_function("deserialize_tag", |b| {
        b.iter(|| {
            let result = Tag::from_vec(&vec);
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
        commitment_hr: commitment_hr.to_vec(),
        commitment_vks: commitment_vks.to_vec(),
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: enc_sender_id.to_vec(),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: signature.to_vec(),
    };

    let sender_tag = SenderTag {
        tag,
        randomness_hr: randomness_hr.to_vec(),
        randomness_vks: randomness_vks.to_vec(),
        vks: random_point(&mut rng),
        proof: proof,
        r_big: random_point(&mut rng),
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
        commitment_hr: commitment_hr.to_vec(),
        commitment_vks: commitment_vks.to_vec(),
        exp_timestamp: 0,
        score: 0,
        enc_sender_id: enc_sender_id.to_vec(),
        q_big: random_point(&mut rng),
        g_prime: random_point(&mut rng),
        x_big: random_point(&mut rng),
        signature: signature.to_vec(),
    };

    let sender_tag = SenderTag {
        tag,
        randomness_hr: randomness_hr.to_vec(),
        randomness_vks: randomness_vks.to_vec(),
        vks: random_point(&mut rng),
        proof: proof,
        r_big: random_point(&mut rng),
    };

    let vec = sender_tag.to_vec();

    c.bench_function("deserialize_full_tag", |b| {
        b.iter(|| {
            let result = SenderTag::from_vec(&vec);
            assert!(result.is_ok());
        });
    });
}

fn end_to_end_bench(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut server = AccountabilityServer::new(
        AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: None,
        },
        &mut rng,
    );
    let sender = Sender::new("sender1", &mut rng);
    server.set_sender_pk(&sender.epk, &sender.handle);
    let verifying_key = server.get_verifying_key();
    let sender_verifying_key = sender.get_verifying_key();

    let receiver_handle = "receiver_handle";

    c.bench_function("end_to_end", |b| {
        b.iter(|| {
            let tag = sender
                .get_tag(receiver_handle, &server, &mut rng)
                .unwrap();
            let _ = tag_verifier::verify(
                receiver_handle,
                &sender_verifying_key,
                &tag.tag,
                &tag.randomness_hr,
                &tag.randomness_vks,
                &tag.proof,
                &tag.r_big,
                &verifying_key,
            );
            let _ = server.report(tag.tag, tag.proof, tag.r_big);
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
