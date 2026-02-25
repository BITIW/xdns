use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct ReplayFilter {
    highest: u64,
    bitmap: u128,
    initialized: bool,
    window: u8,
}

impl ReplayFilter {
    pub fn new(window: u8) -> Self {
        assert!(window > 0 && window <= 128);
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
            window,
        }
    }

    pub fn check_and_mark(&mut self, sequence: u64) -> Result<()> {
        if !self.initialized {
            self.highest = sequence;
            self.bitmap = 1;
            self.initialized = true;
            return Ok(());
        }

        if sequence > self.highest {
            let delta = sequence - self.highest;
            if delta >= 128 {
                self.bitmap = 1;
            } else {
                self.bitmap <<= delta as u32;
                self.bitmap |= 1;
            }
            self.highest = sequence;
            return Ok(());
        }

        let offset = self.highest - sequence;
        if offset >= self.window as u64 {
            bail!("sequence {sequence} is outside replay window");
        }

        let bit = 1_u128 << offset;
        if self.bitmap & bit != 0 {
            bail!("duplicate sequence {sequence}");
        }

        self.bitmap |= bit;
        Ok(())
    }
}
