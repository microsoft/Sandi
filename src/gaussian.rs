use rand::Rng;
use rand_distr::{Distribution, Normal};

pub trait NoiseDistribution: Distribution<f32> + Copy {
    /// Returns the shift parameter m.
    fn m(&self) -> f32;

    /// Returns the maximum value of a sample.
    fn max(&self) -> Option<f32>;

    /// Sample many values.
    fn sample_n<R: Rng + ?Sized>(&self, rng: &mut R, n: usize) -> Vec<f32> {
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
    m: f32,

    /// Optional maximum value of a sample
    max: Option<f32>,

    /// Normal distribution.
    normal: Normal<f32>,
}

impl Gaussian {
    /// Create a new Gaussian noise distribution with standard deviation parameter s.
    pub fn new(m: f32, s: f32) -> Result<Self, String> {
        if m > 0.0 {
            return Err("Gaussian shift parameter m must be non-positive.".to_string());
        }
        if s <= 0.0 {
            return Err("Gaussian standard deviation parameter s must be positive.".to_string());
        }

        let normal = Normal::new(m, s).map_err(|e| e.to_string())?;
        Ok(Gaussian {
            m,
            max: None,
            normal,
        })
    }

    pub fn new_max(m: f32, s: f32, max: f32) -> Result<Self, String> {
        if m > 0.0 {
            return Err("Gaussian shift parameter m must be non-positive.".to_string());
        }
        if s <= 0.0 {
            return Err("Gaussian standard deviation parameter s must be positive.".to_string());
        }

        let normal = Normal::new(m, s).map_err(|e| e.to_string())?;
        Ok(Gaussian {
            m,
            max: Some(max),
            normal,
        })
    }
}

impl Distribution<f32> for Gaussian {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f32 {
        let mut max = f32::MAX;
        if let Some(m) = self.max {
            max = m;
        }
        
        let mut gaussian_sample = self.normal.sample(rng);
        while gaussian_sample > max {
            gaussian_sample = self.normal.sample(rng);
        }

        gaussian_sample
    }
}

impl NoiseDistribution for Gaussian {
    fn m(&self) -> f32 {
        self.m
    }

    fn max(&self) -> Option<f32> {
        self.max
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_gaussian_max() {
        let mut rng = OsRng;
        let gaussian = Gaussian::new(-8.0, 10.0).unwrap();

        let mut some_value = false;
        for _ in 0..1000 {
            let val = gaussian.sample(&mut rng);
            if val > -5.0 {
                // Found a value bigger than -5.0
                some_value = true;
            }
        }
        // At least one value above -5.0
        assert!(some_value);

        let gaussian = Gaussian::new_max(-8.0, 10.0, -5.0).unwrap();
        for _ in 0..1000 {
            // No value should be above -5.0
            assert!(gaussian.sample(&mut rng) < -5.0);
        }
    }
}
