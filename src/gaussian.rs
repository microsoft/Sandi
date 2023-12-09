//use num_traits::Zero;
use rand::Rng;
use rand_distr::{Distribution, Normal};

pub trait NoiseDistribution: Distribution<usize> + Copy {
    /// Returns the shift parameter m.
    fn m(&self) -> i64;

    /// Sample many values.
    fn sample_n<R: Rng + ?Sized>(&self, rng: &mut R, n: usize) -> Vec<usize> {
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            samples.push(self.sample(rng));
        }
        samples
    }
}

/// Gaussian noise distribution.
#[derive(Clone, Copy)]
pub struct Gaussian {
    /// The shift parameter m (non-positive).
    m: i64,

    /// A float version of the shift parameter m (non-positive).
    m_f64: f64,

    /// The standard deviation parameter s (positive).
    s: f64,

    /// Normal distribution.
    normal: Normal<f64>,
}

impl Gaussian {
    /// Create a new Gaussian noise distribution with standard deviation parameter s.
    pub fn new(m: i64, s: f64) -> Result<Self, String> {
        if m <= 0 {
            if s > 0.0 {
                let normal = Normal::new(0.0, s).map_err(|e| e.to_string())?;
                Ok(Gaussian {
                    m,
                    m_f64: m as f64,
                    s,
                    normal,
                })
            } else {
                Err("Gaussian standard deviation parameter s must be positive.".to_string())
            }
        } else {
            Err("Gaussian shift parameter m must be non-positive.".to_string())
        }
    }
}

impl Distribution<usize> for Gaussian {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        let mut gaussian_sample = self.normal.sample(rng);
        while gaussian_sample < self.m_f64 {
            gaussian_sample = self.normal.sample(rng);
        }

        // Shift the sample.
        (gaussian_sample - self.m_f64).round() as usize
    }
}

impl NoiseDistribution for Gaussian {
    fn m(&self) -> i64 {
        self.m
    }
}
