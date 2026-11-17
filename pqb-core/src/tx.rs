//! Incremental parsers for transaction bytes streamed over many APDUs.
//!
//! Nothing here buffers a whole transaction: a PQB vault script alone is 4.9 kB,
//! more than a Nano can spare. Bytes are hashed and inspected as they arrive,
//! and only the fields the review needs are kept.

use crate::error::{Error, Result};
use crate::hash::{finalize_double, Hashes, Sha256};
use crate::script::{SmallScript, SMALL_SCRIPT_MAX};
use crate::template::SCRIPT_LEN;
use crate::varint::{self, VarIntReader};

/// Receives the outputs an `OutputsParser` walks through.
pub trait OutputVisitor {
    fn value(&mut self, index: u64, value: u64) -> Result<()>;
    fn script_begin(&mut self, index: u64, len: u64) -> Result<()>;
    fn script_data(&mut self, index: u64, data: &[u8]) -> Result<()>;
    fn end(&mut self, index: u64) -> Result<()>;
}

#[derive(Clone, Copy)]
enum OutState {
    Value(u8),
    ScriptLen(VarIntReader),
    Script(u64),
    Done,
}

/// Walks a known number of serialized outputs (`value || CompactSize len || script`).
pub struct OutputsParser {
    count: u64,
    index: u64,
    state: OutState,
    value: [u8; 8],
}

impl OutputsParser {
    pub fn new(count: u64) -> Self {
        OutputsParser {
            count,
            index: 0,
            state: if count == 0 {
                OutState::Done
            } else {
                OutState::Value(0)
            },
            value: [0; 8],
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, OutState::Done)
    }

    /// Consume bytes until the last output ends. Returns how many bytes were used.
    pub fn feed<V: OutputVisitor>(&mut self, data: &[u8], visitor: &mut V) -> Result<usize> {
        let mut pos = 0;
        while pos < data.len() {
            match self.state {
                OutState::Value(got) => {
                    let got = got as usize;
                    let take = (8 - got).min(data.len() - pos);
                    self.value[got..got + take].copy_from_slice(&data[pos..pos + take]);
                    pos += take;
                    if got + take == 8 {
                        visitor.value(self.index, u64::from_le_bytes(self.value))?;
                        self.state = OutState::ScriptLen(VarIntReader::new());
                    } else {
                        self.state = OutState::Value((got + take) as u8);
                    }
                }
                OutState::ScriptLen(mut reader) => {
                    let (used, len) = reader.feed(&data[pos..])?;
                    pos += used;
                    match len {
                        None => self.state = OutState::ScriptLen(reader),
                        Some(len) => {
                            visitor.script_begin(self.index, len)?;
                            if len == 0 {
                                self.end_output(visitor)?;
                            } else {
                                self.state = OutState::Script(len);
                            }
                        }
                    }
                }
                OutState::Script(left) => {
                    let take = left.min((data.len() - pos) as u64) as usize;
                    visitor.script_data(self.index, &data[pos..pos + take])?;
                    pos += take;
                    if left == take as u64 {
                        self.end_output(visitor)?;
                    } else {
                        self.state = OutState::Script(left - take as u64);
                    }
                }
                OutState::Done => break,
            }
        }
        Ok(pos)
    }

    fn end_output<V: OutputVisitor>(&mut self, visitor: &mut V) -> Result<()> {
        visitor.end(self.index)?;
        self.index += 1;
        self.state = if self.index == self.count {
            OutState::Done
        } else {
            OutState::Value(0)
        };
        Ok(())
    }
}

/// What a streamed output script turned out to be.
pub struct Captured {
    /// The script itself, when it is short enough to keep.
    pub small: Option<SmallScript>,
    /// SHA-256 of the script, when it has a PQB vault script's length. The caller
    /// compares it with the script hash it derived for the vault it expects.
    pub vault_hash: Option<[u8; 32]>,
}

/// Keeps a short script verbatim and hashes one of a vault script's length.
pub struct ScriptCapture<H: Hashes> {
    len: u64,
    got: usize,
    small: [u8; SMALL_SCRIPT_MAX],
    hash: Option<H::Sha256>,
}

impl<H: Hashes> ScriptCapture<H> {
    pub fn new() -> Self {
        ScriptCapture {
            len: 0,
            got: 0,
            small: [0; SMALL_SCRIPT_MAX],
            hash: None,
        }
    }

    pub fn begin(&mut self, len: u64) {
        self.len = len;
        self.got = 0;
        self.hash = (len == SCRIPT_LEN as u64).then(H::Sha256::new);
    }

    pub fn update(&mut self, data: &[u8]) {
        if self.len <= SMALL_SCRIPT_MAX as u64 {
            self.small[self.got..self.got + data.len()].copy_from_slice(data);
            self.got += data.len();
        }
        if let Some(h) = self.hash.as_mut() {
            h.update(data);
        }
    }

    pub fn finish(&mut self) -> Captured {
        let small = if self.len <= SMALL_SCRIPT_MAX as u64 {
            SmallScript::new(&self.small[..self.len as usize])
        } else {
            None
        };
        let vault_hash = self.hash.take().map(|h| h.finalize());
        Captured { small, vault_hash }
    }
}

impl<H: Hashes> Default for ScriptCapture<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Captures one output, by index, of a transaction being walked.
struct Target<H: Hashes> {
    vout: u64,
    value: Option<u64>,
    script: ScriptCapture<H>,
    captured: Option<Captured>,
    /// Also receives the output's script, as a scriptCode: CompactSize length, then bytes.
    tee: Option<H::Sha256>,
}

impl<H: Hashes> OutputVisitor for Target<H> {
    fn value(&mut self, index: u64, value: u64) -> Result<()> {
        if index == self.vout {
            self.value = Some(value);
        }
        Ok(())
    }
    fn script_begin(&mut self, index: u64, len: u64) -> Result<()> {
        if index == self.vout {
            self.script.begin(len);
            if let Some(tee) = self.tee.as_mut() {
                let (buf, n) = varint::encode(len);
                tee.update(&buf[..n]);
            }
        }
        Ok(())
    }
    fn script_data(&mut self, index: u64, data: &[u8]) -> Result<()> {
        if index == self.vout {
            self.script.update(data);
            if let Some(tee) = self.tee.as_mut() {
                tee.update(data);
            }
        }
        Ok(())
    }
    fn end(&mut self, index: u64) -> Result<()> {
        if index == self.vout {
            self.captured = Some(self.script.finish());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PrevState {
    Version(u8),
    VinCount(VarIntReader),
    Prevout(u8),
    ScriptSigLen(VarIntReader),
    ScriptSig(u64),
    Sequence(u8),
    VoutCount(VarIntReader),
    Outputs,
    Locktime(u8),
    Done,
}

/// The output a previous transaction proved.
pub struct PrevOut<H: Hashes> {
    /// The txid in serialization (internal) byte order.
    pub txid: [u8; 32],
    pub value: u64,
    pub script: Captured,
    /// The hasher passed to `with_tee`, having received the output's script.
    pub tee: Option<H::Sha256>,
}

/// Parses a previous transaction in its legacy (witness-stripped) serialization,
/// hashing it to its txid and keeping output `vout`.
///
/// The txid commits to exactly these bytes, so a host cannot misstate the amount
/// or script of the output an input spends. The witness serialization is refused:
/// a zero input count reads as the segwit marker and is rejected.
pub struct PrevTxParser<H: Hashes> {
    txid: H::Sha256,
    state: PrevState,
    vin_left: u64,
    outputs: OutputsParser,
    target: Target<H>,
}

impl<H: Hashes> PrevTxParser<H> {
    pub fn new(vout: u32) -> Self {
        Self::build(vout, None)
    }

    /// Also feed output `vout`'s script, length-prefixed, to `tee`.
    pub fn with_tee(vout: u32, tee: H::Sha256) -> Self {
        Self::build(vout, Some(tee))
    }

    fn build(vout: u32, tee: Option<H::Sha256>) -> Self {
        PrevTxParser {
            txid: H::Sha256::new(),
            state: PrevState::Version(0),
            vin_left: 0,
            outputs: OutputsParser::new(0),
            target: Target {
                vout: vout as u64,
                value: None,
                script: ScriptCapture::new(),
                captured: None,
                tee,
            },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, PrevState::Done)
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        let mut pos = 0;
        while pos < data.len() {
            let rest = data.len() - pos;
            match self.state {
                PrevState::Version(got) => {
                    let take = (4 - got as usize).min(rest);
                    pos += take;
                    self.state = if got as usize + take == 4 {
                        PrevState::VinCount(VarIntReader::new())
                    } else {
                        PrevState::Version(got + take as u8)
                    };
                }
                PrevState::VinCount(mut reader) => {
                    let (used, n) = reader.feed(&data[pos..])?;
                    pos += used;
                    self.state = match n {
                        None => PrevState::VinCount(reader),
                        Some(0) => return Err(Error::Parse),
                        Some(n) => {
                            self.vin_left = n;
                            PrevState::Prevout(0)
                        }
                    };
                }
                PrevState::Prevout(got) => {
                    let take = (36 - got as usize).min(rest);
                    pos += take;
                    self.state = if got as usize + take == 36 {
                        PrevState::ScriptSigLen(VarIntReader::new())
                    } else {
                        PrevState::Prevout(got + take as u8)
                    };
                }
                PrevState::ScriptSigLen(mut reader) => {
                    let (used, len) = reader.feed(&data[pos..])?;
                    pos += used;
                    self.state = match len {
                        None => PrevState::ScriptSigLen(reader),
                        Some(0) => PrevState::Sequence(0),
                        Some(len) => PrevState::ScriptSig(len),
                    };
                }
                PrevState::ScriptSig(left) => {
                    let take = left.min(rest as u64);
                    pos += take as usize;
                    self.state = if take == left {
                        PrevState::Sequence(0)
                    } else {
                        PrevState::ScriptSig(left - take)
                    };
                }
                PrevState::Sequence(got) => {
                    let take = (4 - got as usize).min(rest);
                    pos += take;
                    self.state = if got as usize + take < 4 {
                        PrevState::Sequence(got + take as u8)
                    } else {
                        self.vin_left -= 1;
                        if self.vin_left == 0 {
                            PrevState::VoutCount(VarIntReader::new())
                        } else {
                            PrevState::Prevout(0)
                        }
                    };
                }
                PrevState::VoutCount(mut reader) => {
                    let (used, n) = reader.feed(&data[pos..])?;
                    pos += used;
                    self.state = match n {
                        None => PrevState::VoutCount(reader),
                        Some(n) if n == 0 || self.target.vout >= n => return Err(Error::Parse),
                        Some(n) => {
                            self.outputs = OutputsParser::new(n);
                            PrevState::Outputs
                        }
                    };
                }
                PrevState::Outputs => {
                    pos += self.outputs.feed(&data[pos..], &mut self.target)?;
                    if self.outputs.is_done() {
                        self.state = PrevState::Locktime(0);
                    }
                }
                PrevState::Locktime(got) => {
                    let take = (4 - got as usize).min(rest);
                    pos += take;
                    self.state = if got as usize + take == 4 {
                        PrevState::Done
                    } else {
                        PrevState::Locktime(got + take as u8)
                    };
                }
                PrevState::Done => return Err(Error::Parse),
            }
        }
        self.txid.update(data);
        Ok(())
    }

    pub fn finish(self) -> Result<PrevOut<H>> {
        if !self.is_done() {
            return Err(Error::Parse);
        }
        let txid = finalize_double::<H>(self.txid);
        match (self.target.value, self.target.captured) {
            (Some(value), Some(script)) => Ok(PrevOut {
                txid,
                value,
                script,
                tee: self.target.tee,
            }),
            _ => Err(Error::Parse),
        }
    }
}
