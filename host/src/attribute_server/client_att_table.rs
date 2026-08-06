use bt_hci::param::ConnHandle;
use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use super::{AttributeData, AttributeTable, Client};
use crate::att::AttErrorCode;
use crate::config::CLIENT_ATT_TABLE_SIZE;
use crate::{Error, Identity};

const HEADER_SIZE: usize = core::mem::size_of::<Header>();
const ENTRY_SIZE: usize = core::mem::size_of::<Entry>();
const VARIABLE_LEN_FLAG: u16 = 0x8000;

/// A compact, fixed-size map of client-specific attribute values (e.g. CCCDs).
///
/// Entries are stored in a flat byte buffer with a sorted index for binary-search lookups.
/// [`CLIENT_ATT_TABLE_SIZE`] determines the total storage available for both the index and values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
#[repr(align(2))]
pub struct ClientAttTable {
    buf: [u8; CLIENT_ATT_TABLE_SIZE],
}

impl ClientAttTable {
    /// Creates a new [`ClientAttTableBuilder`] for constructing a `ClientAttTable`.
    pub const fn builder() -> ClientAttTableBuilder {
        const { core::assert!(CLIENT_ATT_TABLE_SIZE >= HEADER_SIZE && CLIENT_ATT_TABLE_SIZE <= u16::MAX as usize) };

        ClientAttTableBuilder {
            buf: [0; CLIENT_ATT_TABLE_SIZE],
            values_len: 0,
        }
    }

    /// Get a read-only view of the table
    pub const fn view(&self) -> ClientAttTableView<'_> {
        ClientAttTableView { buf: &self.buf }
    }

    const fn header(&self) -> Header {
        self.view().header()
    }

    // If `i` is a variable length attribute, set its length to `len`. For fixed length attributes, do nothing.
    fn set_variable_len(&mut self, i: usize, len: u16) {
        assert!(len as usize <= self.view().value_capacity(i));
        if self.view().index()[i].is_variable_len() {
            let start = self.view().raw_value_start(i);
            self.buf[start..][..2].copy_from_slice(&len.to_le_bytes());
        }
    }

    /// Returns a reference to the value associated with the given attribute handle, or `None` if not found.
    pub fn get(&self, key: u16) -> Option<&[u8]> {
        self.view().get(key)
    }

    /// Writes `data` to `key` starting at `offset`.
    pub fn write(&mut self, key: u16, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if key >= VARIABLE_LEN_FLAG {
            return Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
        }

        let i = self.view().find(key).ok_or(AttErrorCode::ATTRIBUTE_NOT_FOUND)?;
        if offset > self.view().value_len(i) {
            Err(AttErrorCode::INVALID_OFFSET)
        } else if offset + data.len() > self.view().value_capacity(i) {
            Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
        } else {
            let start = self.view().value_start(i) + offset;
            let end = start + data.len();
            self.buf[start..end].copy_from_slice(data);

            self.set_variable_len(i, (offset + data.len()) as u16);

            Ok(())
        }
    }

    /// Copies values from `src` into this map for all matching keys.
    ///
    /// Keys present in this map but not in `src` are zeroed. If value sizes differ,
    /// only the smaller length is copied and the remainder is zeroed.
    pub fn set_values(&mut self, src: &ClientAttTableView<'_>) {
        for i in 0..self.header().att_count() {
            let view = self.view();
            let key = view.index()[i].key();
            match src.get(key) {
                Some(src) => {
                    let start = view.value_start(i);
                    let capacity = view.value_capacity(i);
                    let dest = &mut self.buf[start..][..capacity];

                    let copy_len = dest.len().min(src.len());
                    dest[..copy_len].copy_from_slice(&src[..copy_len]);
                    dest[copy_len..].fill(0);

                    self.set_variable_len(i, copy_len as u16);
                }
                None => {
                    let start = view.raw_value_start(i);
                    let end = view.value_end(i);
                    self.buf[start..end].fill(0);
                }
            }
        }
    }

    /// Zeros all values in the map, leaving the index structure intact.
    pub fn clear(&mut self) {
        let header = self.header();
        self.buf[header.values_base()..header.values_end()].fill(0);
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &[u8] {
        self.view().raw()
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Header([u8; 4]);

impl Header {
    const fn att_count(&self) -> usize {
        u16::from_le_bytes([self.0[0], self.0[1]]) as usize
    }

    const fn values_base(&self) -> usize {
        HEADER_SIZE + self.att_count() * ENTRY_SIZE
    }

    const fn values_len(&self) -> usize {
        u16::from_le_bytes([self.0[2], self.0[3]]) as usize
    }

    const fn values_end(&self) -> usize {
        self.values_base() + self.values_len()
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Entry([u8; 4]);

impl Entry {
    const fn key(&self) -> u16 {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        key & !VARIABLE_LEN_FLAG
    }

    const fn offset(&self) -> usize {
        u16::from_le_bytes([self.0[2], self.0[3]]) as usize
    }

    const fn is_variable_len(&self) -> bool {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        (key & VARIABLE_LEN_FLAG) != 0
    }

    const fn set(&mut self, key: u16, offset: u16, variable_len: bool) {
        let flag = if variable_len { VARIABLE_LEN_FLAG } else { 0 };
        let key = (key | flag).to_le_bytes();
        let offset = offset.to_le_bytes();
        self.0 = [key[0], key[1], offset[0], offset[1]];
    }
}

/// A read-only view over a serialized [`ClientAttTable`].
///
/// The view borrows the raw table format directly: a little-endian entry count, a little-endian value byte length, a
/// sorted index of 4-byte entries, and the value bytes. Unlike [`ClientAttTable`], the borrowed bytes may come from
/// arbitrary storage and do not need the owning table's alignment. Use [`try_from_raw()`](Self::try_from_raw) to
/// validate the buffer before reading values.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientAttTableView<'a> {
    buf: &'a [u8],
}

impl<'a> ClientAttTableView<'a> {
    /// Constructs a `ClientAttTableView` from raw serialized table bytes.
    ///
    /// The bytes are typically obtained from [`ClientAttTable::raw()`], but may also come from persistent storage or
    /// another byte buffer. Returns an error if the slice is too short, the index is malformed, or any value length is
    /// outside its encoded capacity.
    pub fn try_from_raw(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidValue);
        }

        let map = Self { buf: data };

        if map.header().values_end() > data.len() {
            return Err(Error::InvalidValue);
        }

        // Validate the index
        let mut last_key = 0;
        let mut last_offset = 0;
        for e in map.index().iter() {
            let key = e.key();
            let offset = e.offset();
            if key <= core::mem::replace(&mut last_key, key)
                || offset < core::mem::replace(&mut last_offset, offset)
                || offset > map.header().values_len()
            {
                return Err(Error::InvalidValue);
            }
        }

        // Validate variable length attributes
        for i in 0..map.header().att_count() {
            if map.value_end(i) < map.value_start(i) || map.value_len(i) > map.value_capacity(i) {
                return Err(Error::InvalidValue);
            }
        }

        Ok(map)
    }

    const fn header(&self) -> Header {
        Header([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
    }

    fn index(&self) -> &[Entry] {
        let header = self.header();
        let chunks = self.buf[HEADER_SIZE..header.values_base()].as_chunks::<ENTRY_SIZE>().0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; ENTRY_SIZE], so it has the same size and
        // alignment as [u8; ENTRY_SIZE]. Every ENTRY_SIZE-byte chunk is therefore aligned and valid for reads as a
        // ClientAttTableEntry.
        unsafe { core::slice::from_raw_parts(chunks.as_ptr().cast::<Entry>(), chunks.len()) }
    }

    fn raw_value_start(&self, i: usize) -> usize {
        let header = self.header();
        let entry = self.index()[i];
        entry.offset() + header.values_base()
    }

    fn value_start(&self, i: usize) -> usize {
        let header = self.header();
        let entry = self.index()[i];
        let start = entry.offset() + header.values_base();
        if entry.is_variable_len() {
            start + 2
        } else {
            start
        }
    }

    fn value_end(&self, i: usize) -> usize {
        let header = self.header();
        self.index()
            .get(i + 1)
            .map(Entry::offset)
            .unwrap_or(header.values_len())
            + header.values_base()
    }

    fn value_capacity(&self, i: usize) -> usize {
        self.value_end(i).saturating_sub(self.value_start(i))
    }

    fn value_len(&self, i: usize) -> usize {
        let index = self.index();
        if index[i].is_variable_len() {
            let start = self.raw_value_start(i);
            u16::from_le_bytes([self.buf[start], self.buf[start + 1]]) as usize
        } else {
            self.value_capacity(i)
        }
    }

    fn find(&self, key: u16) -> Option<usize> {
        self.index().binary_search_by_key(&key, Entry::key).ok()
    }

    /// Returns a reference to the value associated with the given attribute handle, or `None` if not found.
    pub fn get(&self, key: u16) -> Option<&'a [u8]> {
        if key >= VARIABLE_LEN_FLAG {
            None
        } else {
            let i = self.find(key)?;
            Some(&self.buf[self.value_start(i)..][..self.value_len(i)])
        }
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &'a [u8] {
        let header = self.header();
        &self.buf[..header.values_end()]
    }
}

/// A builder for [`ClientAttTable`].
///
/// Entries must be pushed in ascending key order. Use [`build()`](Self::build) to finalize.
#[derive(Debug, Clone)]
pub struct ClientAttTableBuilder {
    buf: [u8; CLIENT_ATT_TABLE_SIZE],
    values_len: u16,
}

impl ClientAttTableBuilder {
    /// Adds an entry with the given attribute handle and value size.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not greater than the previously pushed keys.
    pub fn push(&mut self, key: u16, mut value_len: u16, variable_len: bool) {
        assert!(value_len <= 512, "Bluetooth attributes must be at most 512 bytes");
        assert!(key > 0, "Bluetooth handles must be greater than 0");
        assert!(key <= 0x7fff, "Handle values above 0x7fff are reserved");

        let old_att_count = self.att_count();
        self.set_att_count(old_att_count + 1);
        let offset = self.values_len;

        if variable_len {
            value_len += 2;
        }

        self.values_len = self
            .values_len
            .checked_add(value_len)
            .expect("ClientAttTable buffer overflow");
        self.set_values_len(self.values_len);

        // If we overflow, just keep tracking the total needed size so we can report it in build()
        if self.end() <= CLIENT_ATT_TABLE_SIZE {
            let index = self.index_mut();
            if old_att_count > 0 {
                let last_key = index[old_att_count - 1].key();
                assert!(key > last_key, "keys must be inserted in ascending order");
            }
            index[old_att_count].set(key, offset, variable_len);
        }
    }

    /// Consumes the builder and returns the completed [`ClientAttTable`].
    pub fn build(self) -> ClientAttTable {
        let end = self.end();
        if end > CLIENT_ATT_TABLE_SIZE {
            panic!(
                "ClientAttTable buffer ({} bytes) overflow. Need {} bytes for exact size",
                CLIENT_ATT_TABLE_SIZE, end
            );
        } else if end < CLIENT_ATT_TABLE_SIZE {
            warn!(
                "ClientAttTable buffer ({} bytes) oversized. Only need {} bytes for exact size",
                CLIENT_ATT_TABLE_SIZE, end
            );
        }

        ClientAttTable { buf: self.buf }
    }

    const fn att_count(&self) -> usize {
        u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize
    }

    fn set_att_count(&mut self, len: usize) {
        self.buf[..2].copy_from_slice(&(len as u16).to_le_bytes())
    }

    fn set_values_len(&mut self, len: u16) {
        self.buf[2..4].copy_from_slice(&len.to_le_bytes())
    }

    const fn index_mut(&mut self) -> &mut [Entry] {
        let end = self.att_count() * ENTRY_SIZE;
        let (_, slice) = self.buf.split_at_mut(HEADER_SIZE);
        let (slice, _) = slice.split_at_mut(end);
        let chunks = slice.as_chunks_mut::<ENTRY_SIZE>().0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; ENTRY_SIZE], so it has the same size and
        // alignment as [u8; ENTRY_SIZE]. The mutable chunks come from the table's uniquely borrowed buffer, so the
        // returned entries are uniquely borrowed for the same lifetime.
        unsafe { core::slice::from_raw_parts_mut(chunks.as_mut_ptr() as *mut _, chunks.len()) }
    }

    const fn values_base(&self) -> usize {
        HEADER_SIZE + self.att_count() * ENTRY_SIZE
    }

    const fn end(&self) -> usize {
        self.values_base() + self.values_len as usize
    }
}

/// A table of CCCD values for each connected client.
pub(crate) struct ClientAttTables<M: RawMutex, const CONN_MAX: usize> {
    state: Mutex<M, RefCell<[(Client, ClientAttTable); CONN_MAX]>>,
}

impl<M: RawMutex, const CONN_MAX: usize> ClientAttTables<M, CONN_MAX> {
    pub(crate) fn new<const ATT_MAX: usize>(att_table: &AttributeTable<'_, M, ATT_MAX>) -> Self {
        let mut builder = ClientAttTable::builder();
        att_table.iterate(|at| {
            for (handle, att) in at {
                if let AttributeData::ClientSpecific { variable_len, capacity } = att.data {
                    builder.push(handle, capacity, variable_len);
                }
            }
        });
        let base = builder.build();
        let values: [(Client, ClientAttTable); CONN_MAX] = core::array::from_fn(|_| (Client::default(), base.clone()));
        Self {
            state: Mutex::new(RefCell::new(values)),
        }
    }

    pub(crate) fn connect(&self, handle: ConnHandle, peer_identity: &Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            trace!("[server] searching for peer {:?}", peer_identity);
            let mut n = n.borrow_mut();
            let empty_slot = Identity::default();
            // Bump on every claim so the reclaim path below can pick the
            // least-recently-claimed slot instead of a fixed one.
            let seq = n.iter().map(|(c, _)| c.seq).max().unwrap_or(0).wrapping_add(1);

            // 1. This handle already owns a slot. Only reachable if a link is
            //    re-registered without an intervening disconnect; make it a
            //    no-op rather than a second slot for the same link.
            for (client, _) in n.iter_mut() {
                if client.handle == Some(handle) {
                    trace!("[server] slot already held by this link");
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    client.seq = seq;
                    return Ok(());
                }
            }
            // 2. Same peer as a PREVIOUS link (a reconnecting bonded central) —
            //    keep its cached CCCDs and re-point the slot at the new handle.
            //
            //    ⚠️ Two guards, both load-bearing:
            //    * `handle.is_none()` — a slot owned by a LIVE link must never
            //      be stolen on an identity match, or the peer that owned it is
            //      silently orphaned.
            //    * `!peer_identity.is_unset()` — a connection reports the
            //      DEFAULT identity until its link encrypts, and
            //      `Identity::default().match_identity(&default)` is TRUE. So
            //      without this, every not-yet-encrypted connection matched
            //      every other one and they all collapsed onto a single slot;
            //      the last to connect took it and the rest were left with no
            //      slot at all. Their CCCD writes then failed with ATT
            //      `Attribute Not Found (0x0a)` and they never received a single
            //      notification. HW-measured with two centrals: 28 CCCD writes,
            //      28 × 0x0a, 0 notifications on the orphaned link, while the
            //      other link wrote the SAME handles with 0 errors.
            if !peer_identity.is_unset() {
                for (client, _) in n.iter_mut() {
                    if client.handle.is_none() && client.identity.match_identity(peer_identity) {
                        trace!("[server] reusing slot for peer {:?}", peer_identity);
                        client.is_connected = true;
                        client.handle = Some(handle);
                        client.set_identity(*peer_identity);
                        client.seq = seq;
                        return Ok(());
                    }
                }
            }
            // 3. A never-used slot.
            for (client, _) in n.iter_mut() {
                if client.handle.is_none() && client.identity == empty_slot {
                    trace!("[server] empty slot: connecting");
                    client.is_connected = true;
                    client.handle = Some(handle);
                    client.set_identity(*peer_identity);
                    client.seq = seq;
                    return Ok(());
                }
            }
            trace!("[server] all slots full...");
            // 4. All slots are taken; evict one whose link is gone.
            for (client, table) in n.iter_mut() {
                if !client.is_connected {
                    trace!("[server] booting disconnected peer {:?}", client.identity);
                    *client = Client::default();
                    client.is_connected = true;
                    client.handle = Some(handle);
                    client.set_identity(*peer_identity);
                    client.seq = seq;
                    // erase the previous client's config
                    table.clear();
                    return Ok(());
                }
            }
            // 5. Every slot still claims to be connected. This connect() is only
            // reached for a link the CONTROLLER already ADMITTED, and the
            // controller enforces the same CONN_MAX cap, so at least one slot
            // must be stale. Refusing would permanently WEDGE the GATT server
            // (every later client rejected — a reconnecting central could DoS
            // the device), so reclaim instead.
            //
            // ⚠️ Which slot we reclaim is NOT arbitrary. This used to take
            // `iter_mut().next()` — ALWAYS SLOT 0 — which happily evicted a
            // LIVE peer: with two centrals connected, both landed on slot 0 and
            // the second overwrote the first's identity and cleared its CCCDs.
            // `should_notify` then missed for that peer forever and `notify_raw`
            // turned every notification into a successful-looking no-op, so one
            // companion silently received NOTHING (HW-measured: 521 dropped
            // notifications to the second central, zero to the first).
            // Evict the LEAST-RECENTLY-CLAIMED slot instead: live links are
            // re-stamped on every connect, so the oldest is the stale one.
            if let Some((client, table)) = n.iter_mut().min_by_key(|(c, _)| c.seq) {
                warn!(
                    "[server] all attribute slots claim connected but a new connection was \
                     admitted — reclaiming the least-recently-claimed slot (prevents GATT-server wedge)"
                );
                *client = Client::default();
                client.is_connected = true;
                client.handle = Some(handle);
                client.set_identity(*peer_identity);
                client.seq = seq;
                table.clear();
                return Ok(());
            }
            Err(Error::ConnectionLimitReached)
        })
    }

    pub(crate) fn disconnect(&self, handle: ConnHandle, peer_identity: &Identity, bonded: bool) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                // Match on the HANDLE first. Identity is not stable across a
                // link (raw connection address before encryption, bonded
                // identity after; RPA peers rotate theirs), so an
                // identity-only match silently missed whenever the identity had
                // moved — leaving `is_connected` set forever, leaking the slot,
                // and eventually forcing every connect down the reclaim path
                // above. The handle is controller-assigned and byte-identical
                // at connect and disconnect. Identity remains as a fallback for
                // a slot claimed before handles were tracked.
                if client.handle == Some(handle)
                    || (client.handle.is_none() && client.identity.match_identity(peer_identity))
                {
                    // Release the LINK but KEEP the cached CCCDs, bonded or not.
                    //
                    // Wiping an unbonded peer's slot here looked spec-tidy but
                    // punishes the common case: a link that drops before (or
                    // while) its bond state is evaluated reads as unbonded, so
                    // an ordinary reconnect came back to a PRISTINE slot and the
                    // companion was left silently unsubscribed. Clear LAZILY
                    // instead — when a DIFFERENT peer actually reuses the slot
                    // (paths 4/5 in `connect`). That is equally correct for an
                    // unbonded client and cannot punish a reconnect.
                    //
                    // Invisible while the table had a single slot: every
                    // connection resolved to it and so always found the previous
                    // CCCDs, however wrong the accounting was.
                    let _ = bonded;
                    client.is_connected = false;
                    client.handle = None;
                    break;
                }
            }
        })
    }

    pub(crate) fn with_value<R>(
        &self,
        handle: ConnHandle,
        peer_identity: &Identity,
        att_handle: u16,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Option<R> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.owns(handle, peer_identity) {
                    return table.get(att_handle).map(f);
                }
            }
            None
        })
    }

    pub(crate) fn read(
        &self,
        handle: ConnHandle,
        peer_identity: &Identity,
        att_handle: u16,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, AttErrorCode> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.owns(handle, peer_identity) {
                    let value = table.get(att_handle).ok_or(AttErrorCode::ATTRIBUTE_NOT_FOUND)?;
                    if offset > value.len() {
                        return Err(AttErrorCode::INVALID_OFFSET);
                    }
                    let value = &value[offset..];
                    let len = value.len().min(data.len());
                    data[..len].copy_from_slice(value);
                    return Ok(len);
                }
            }
            Err(AttErrorCode::ATTRIBUTE_NOT_FOUND)
        })
    }

    pub(crate) fn write(
        &self,
        handle: ConnHandle,
        peer_identity: &Identity,
        att_handle: u16,
        offset: usize,
        data: &[u8],
    ) -> Result<(), AttErrorCode> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.owns(handle, peer_identity) {
                    return table.write(att_handle, offset, data);
                }
            }
            Err(AttErrorCode::ATTRIBUTE_NOT_FOUND)
        })
    }

    /// CCCDDIAG: does ANY slot own this link, and does that slot hold a value
    /// for `att_handle`? `should_notify` collapses both misses into `false`,
    /// which makes "nobody is subscribed" indistinguishable from "the slot that
    /// held the subscription is gone" — the exact ambiguity behind a peripheral
    /// that ACKs a CCCD enable and then never notifies.
    pub(crate) fn diag_lookup(
        &self,
        handle: ConnHandle,
        peer_identity: &Identity,
        att_handle: u16,
    ) -> (bool, bool) {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.owns(handle, peer_identity) {
                    return (true, table.get(att_handle).is_some());
                }
            }
            (false, false)
        })
    }

    pub(crate) fn get_client_att_table(&self, peer_identity: &Identity) -> Option<ClientAttTable> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return Some(table.clone());
                }
            }
            None
        })
    }

    pub(crate) fn set_client_att_table(&self, peer_identity: &Identity, table: &ClientAttTableView<'_>) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, t) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    trace!("Setting client attribute table {:?} for {:?}", table, peer_identity);
                    t.set_values(table);
                    break;
                }
            }
        })
    }

    pub(crate) fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if identity.match_identity(&client.identity) {
                    client.set_identity(identity);
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientAttTable, ClientAttTableView};
    use crate::att::AttErrorCode;

    /// Regression: two LIVE connections must each keep their own slot, and a
    /// later connect must never evict a live peer's CCCD subscriptions.
    ///
    /// The original allocator reclaimed `iter_mut().next()` — always slot 0 —
    /// whenever every slot claimed `is_connected`. With two centrals attached
    /// they both landed on slot 0, so the second silently wiped the first's
    /// identity and CCCD table. `should_notify` then missed for that peer
    /// forever, and because `notify_raw` treats a miss as success, the peer
    /// received NOTHING while the board logged a clean fan-out.
    #[test]
    fn a_second_connection_does_not_evict_a_live_peers_subscriptions() {
        use bt_hci::param::{AddrKind, BdAddr, ConnHandle};
        use core::cell::RefCell;
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;
        use embassy_sync::blocking_mutex::Mutex;

        use super::{Client, ClientAttTables};
        use crate::{Address, Identity};

        const CCCD: u16 = 53;

        fn ident(last: u8) -> Identity {
            Identity {
                addr: Address::new(AddrKind::PUBLIC, BdAddr::new([1, 2, 3, 4, 5, last])),
                irk: None,
            }
        }

        let mut builder = ClientAttTable::builder();
        builder.push(CCCD, 2, false);
        let base = builder.build();
        // CONN_MAX = 2 so the "all slots claim connected" reclaim path is easy
        // to reach — it is the path that used to destroy a live peer.
        let tables: ClientAttTables<NoopRawMutex, 2> = ClientAttTables {
            state: Mutex::new(RefCell::new(core::array::from_fn(|_| {
                (Client::default(), base.clone())
            }))),
        };

        let (a, b) = (ident(0xAA), ident(0xBB));
        let (ha, hb) = (ConnHandle::new(1), ConnHandle::new(2));

        tables.connect(ha, &a).unwrap();
        tables.connect(hb, &b).unwrap();

        // Both subscribe (CCCD notify bit).
        tables.write(ha, &a, CCCD, 0, &[0x01, 0x00]).unwrap();
        tables.write(hb, &b, CCCD, 0, &[0x01, 0x00]).unwrap();

        let notify = |h, id: &Identity| {
            tables.with_value(h, id, CCCD, |v| {
                let mut o = [0u8; 2];
                o.copy_from_slice(v);
                o
            })
        };
        assert_eq!(notify(ha, &a), Some([0x01u8, 0x00]), "A lost its slot");
        assert_eq!(notify(hb, &b), Some([0x01u8, 0x00]), "B lost its slot");

        // A third peer arrives while both slots are live — the reclaim path.
        // It must take a slot, and it must not silently orphan BOTH peers.
        let c = ident(0xCC);
        let hc = ConnHandle::new(3);
        tables.connect(hc, &c).unwrap();
        tables.write(hc, &c, CCCD, 0, &[0x01, 0x00]).unwrap();
        assert_eq!(notify(hc, &c), Some([0x01u8, 0x00]));
        // The least-recently-claimed slot (A) is the victim; the more recent
        // live peer B survives. Under the old always-slot-0 rule both A and B
        // ended up sharing one slot and B was the one destroyed.
        assert_eq!(notify(hb, &b), Some([0x01u8, 0x00]), "a live peer was evicted");
    }

    /// Regression: two connections that have not yet encrypted BOTH report the
    /// DEFAULT identity, and `Identity::default().match_identity(&default)` is
    /// true — so an identity-keyed reuse collapsed them onto ONE slot. The
    /// second to connect took it; the first was left with no slot at all, its
    /// CCCD writes were rejected with ATT `Attribute Not Found (0x0a)`, and it
    /// never received a single notification.
    #[test]
    fn two_unresolved_connections_do_not_collapse_onto_one_slot() {
        use bt_hci::param::ConnHandle;
        use core::cell::RefCell;
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;
        use embassy_sync::blocking_mutex::Mutex;

        use super::{Client, ClientAttTables};
        use crate::Identity;

        const CCCD: u16 = 53;
        let mut builder = ClientAttTable::builder();
        builder.push(CCCD, 2, false);
        let base = builder.build();
        let tables: ClientAttTables<NoopRawMutex, 2> = ClientAttTables {
            state: Mutex::new(RefCell::new(core::array::from_fn(|_| {
                (Client::default(), base.clone())
            }))),
        };

        // Neither link has encrypted yet, so both report the default identity.
        let unset = Identity::default();
        let (h1, h2) = (ConnHandle::new(1), ConnHandle::new(2));
        tables.connect(h1, &unset).unwrap();
        tables.connect(h2, &unset).unwrap();

        // BOTH must be able to subscribe — this is the write that used to fail
        // with ATTRIBUTE_NOT_FOUND for whichever link lost the race.
        tables.write(h1, &unset, CCCD, 0, &[0x01, 0x00]).unwrap();
        tables.write(h2, &unset, CCCD, 0, &[0x01, 0x00]).unwrap();

        let notify = |h| {
            tables.with_value(h, &unset, CCCD, |v| {
                let mut o = [0u8; 2];
                o.copy_from_slice(v);
                o
            })
        };
        assert_eq!(notify(h1), Some([0x01u8, 0x00]), "link 1 was orphaned");
        assert_eq!(notify(h2), Some([0x01u8, 0x00]), "link 2 was orphaned");
    }

    /// A disconnect must free the slot even when the peer's identity CHANGED
    /// during the link (raw connection address before encryption, bonded
    /// identity after). Keying on identity alone leaked the slot as
    /// `is_connected` forever, which is what forced every later connect into
    /// the reclaim path in the first place.
    #[test]
    fn disconnect_frees_the_slot_even_if_the_identity_changed_mid_link() {
        use bt_hci::param::{AddrKind, BdAddr, ConnHandle};
        use core::cell::RefCell;
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;
        use embassy_sync::blocking_mutex::Mutex;

        use super::{Client, ClientAttTables};
        use crate::{Address, Identity};

        const CCCD: u16 = 53;
        fn ident(last: u8) -> Identity {
            Identity {
                addr: Address::new(AddrKind::PUBLIC, BdAddr::new([1, 2, 3, 4, 5, last])),
                irk: None,
            }
        }

        let mut builder = ClientAttTable::builder();
        builder.push(CCCD, 2, false);
        let base = builder.build();
        let tables: ClientAttTables<NoopRawMutex, 1> = ClientAttTables {
            state: Mutex::new(RefCell::new(core::array::from_fn(|_| {
                (Client::default(), base.clone())
            }))),
        };

        let h = ConnHandle::new(7);
        tables.connect(h, &ident(0x01)).unwrap();
        // Peer's identity moves to its bonded identity, then the link drops.
        tables.disconnect(h, &ident(0x02), false);

        // The single slot must now be free for a brand-new peer WITHOUT
        // needing the reclaim path.
        let h2 = ConnHandle::new(8);
        tables.connect(h2, &ident(0x03)).unwrap();
        tables.write(h2, &ident(0x03), CCCD, 0, &[0x01, 0x00]).unwrap();
        assert_eq!(
            tables.with_value(h2, &ident(0x03), CCCD, |v| {
                let mut o = [0u8; 2];
                o.copy_from_slice(v);
                o
            }),
            Some([0x01u8, 0x00])
        );

        // ⭐ And the lookup must keep resolving when the peer's identity moves
        // MID-LINK (raw connection address -> bonded identity on encryption).
        // Matching CCCDs by identity alone made the slot unreachable at that
        // instant: the CCCD write landed under one identity and every later
        // `should_notify` looked up the other, missed, and — because a miss is
        // reported as a successful no-op — the peer went silently deaf.
        // HW-measured: the second central of two received NOTHING.
        assert_eq!(
            tables.with_value(h2, &ident(0x99), CCCD, |v| {
                let mut o = [0u8; 2];
                o.copy_from_slice(v);
                o
            }),
            Some([0x01u8, 0x00]),
            "slot became unreachable after the peer identity changed mid-link"
        );
    }

    fn assert_invalid(data: &[u8]) {
        assert!(ClientAttTableView::try_from_raw(data).is_err());
    }

    #[test]
    fn raw_view_uses_declared_values_len_and_ignores_trailing_storage() {
        #[rustfmt::skip]
        let data = [
            2, 0, 5, 0,
            1, 0, 0, 0,
            2, 0x80, 2, 0,
            0xaa, 0xbb, 1, 0, 0xcc,
            0xdd, 0xee,
        ];

        let view = ClientAttTableView::try_from_raw(&data).unwrap();

        assert_eq!(view.raw(), &data[..17]);
        assert_eq!(view.get(1), Some([0xaa, 0xbb].as_slice()));
        assert_eq!(view.get(2), Some([0xcc].as_slice()));
    }

    #[test]
    fn raw_view_rejects_malformed_table_boundaries_and_index() {
        // values_len promises two bytes, but only one is present.
        assert_invalid(&[1, 0, 2, 0, 1, 0, 0, 0, 0]);

        // att_count places the index beyond the provided buffer.
        assert_invalid(&[2, 0, 0, 0, 1, 0, 0, 0]);

        // Keys must be strictly ascending after masking off the variable-length flag.
        #[rustfmt::skip]
        let duplicate_key_after_masking = [
            2, 0, 2, 0,
            1, 0, 0, 0,
            1, 0x80, 1, 0,
            0, 0,
        ];
        assert_invalid(&duplicate_key_after_masking);

        // Offsets must be monotonically increasing and remain within values_len.
        #[rustfmt::skip]
        let decreasing_offset = [
            2, 0, 4, 0,
            1, 0, 2, 0,
            2, 0, 1, 0,
            0, 0, 0, 0,
        ];
        assert_invalid(&decreasing_offset);

        #[rustfmt::skip]
        let offset_past_values_len = [
            1, 0, 1, 0,
            1, 0, 2, 0,
            0,
        ];
        assert_invalid(&offset_past_values_len);
    }

    #[test]
    fn raw_view_rejects_variable_length_exceeding_encoded_capacity() {
        #[rustfmt::skip]
        let data = [
            2, 0, 8, 0,
            1, 0x80, 0, 0,
            2, 0, 6, 0,
            5, 0, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        assert_invalid(&data);
    }

    #[test]
    fn variable_length_writes_append_overwrite_truncate_and_preserve_capacity() {
        let mut builder = ClientAttTable::builder();
        builder.push(1, 4, true);
        let mut table = builder.build();

        assert_eq!(table.get(1), Some([].as_slice()));
        assert_eq!(table.write(1, 1, &[0xaa]), Err(AttErrorCode::INVALID_OFFSET));

        table.write(1, 0, &[1, 2]).unwrap();
        table.write(1, 2, &[3, 4]).unwrap();
        assert_eq!(table.get(1), Some([1, 2, 3, 4].as_slice()));
        assert_eq!(
            table.write(1, 4, &[5]),
            Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
        );

        table.write(1, 1, &[9]).unwrap();
        assert_eq!(table.get(1), Some([1, 9].as_slice()));

        table.write(1, 2, &[7, 8]).unwrap();
        assert_eq!(table.get(1), Some([1, 9, 7, 8].as_slice()));
    }

    #[test]
    fn set_values_copies_matching_keys_truncates_to_capacity_and_zeros_missing_keys() {
        let mut src_builder = ClientAttTable::builder();
        src_builder.push(1, 2, false);
        src_builder.push(2, 5, true);
        src_builder.push(4, 1, false);
        let mut src = src_builder.build();
        src.write(1, 0, &[0x11, 0x22]).unwrap();
        src.write(2, 0, &[0x33, 0x44, 0x55, 0x66, 0x77]).unwrap();
        src.write(4, 0, &[0x88]).unwrap();

        let mut dst_builder = ClientAttTable::builder();
        dst_builder.push(1, 4, false);
        dst_builder.push(2, 3, true);
        dst_builder.push(3, 2, false);
        let mut dst = dst_builder.build();
        dst.write(1, 0, &[0xaa, 0xaa, 0xaa, 0xaa]).unwrap();
        dst.write(2, 0, &[0xbb, 0xbb]).unwrap();
        dst.write(3, 0, &[0xcc, 0xcc]).unwrap();

        dst.set_values(&src.view());

        assert_eq!(dst.get(1), Some([0x11, 0x22, 0, 0].as_slice()));
        assert_eq!(dst.get(2), Some([0x33, 0x44, 0x55].as_slice()));
        assert_eq!(dst.get(3), Some([0, 0].as_slice()));
        assert_eq!(dst.get(4), None);
    }

    #[test]
    fn clear_zeroes_value_region_without_changing_table_shape() {
        let mut builder = ClientAttTable::builder();
        builder.push(1, 2, false);
        builder.push(2, 3, true);
        let mut table = builder.build();
        table.write(1, 0, &[0xaa, 0xbb]).unwrap();
        table.write(2, 0, &[0xcc, 0xdd]).unwrap();
        let raw_len = table.raw().len();
        let mut header_and_index = [0; 12];
        header_and_index.copy_from_slice(&table.raw()[..12]);

        table.clear();

        assert_eq!(table.raw().len(), raw_len);
        assert_eq!(&table.raw()[..12], header_and_index.as_slice());
        assert_eq!(table.get(1), Some([0, 0].as_slice()));
        assert_eq!(table.get(2), Some([].as_slice()));
        assert_eq!(&table.raw()[12..], &[0, 0, 0, 0, 0, 0, 0]);
    }
}
