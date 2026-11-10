import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  FlatList,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { pirRead } from '../pirClient';
import {
  addBurnAddress,
  burnAddress,
  BurnAddressEntry,
  getOrCreateSecretKey,
  listBurnAddresses,
} from '../burn';
import { formatUsd } from '../format';
import { getOrCreateWallet } from '../eth';
import { CHAIN_ID } from '../tokens';

interface Deposit {
  leaf: string; // 0x + 64 hex (32-byte Fr leaf)
}

function toHex(b: Uint8Array): string {
  return '0x' + [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export function BurnScreen() {
  const [tab, setTab] = useState<'create' | 'deposits'>('create');
  const [addresses, setAddresses] = useState<BurnAddressEntry[]>([]);
  const [latest, setLatest] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const [deposits, setDeposits] = useState<Deposit[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const loadAddresses = useCallback(async () => {
    setAddresses(await listBurnAddresses());
  }, []);

  const loadDeposits = useCallback(async () => {
    try {
      const leaf = await pirRead(0, 0); // index 0, level 0 (= leaves)
      setDeposits([{ leaf: toHex(leaf) }]);
    } catch (e) {
      console.warn('pir failed', e);
      setDeposits([]);
    }
  }, []);


  useEffect(() => {
    loadAddresses();
    loadDeposits();
  }, [loadAddresses, loadDeposits]);

  const create = useCallback(async () => {
    setBusy(true);
    try {
      const w = await getOrCreateWallet();
      const secretKey = await getOrCreateSecretKey();
      const i = (await listBurnAddresses()).length;
      const addr = burnAddress(CHAIN_ID, w.address, secretKey, i);
      await addBurnAddress({ address: addr, index: i, createdAt: Date.now() });
      setLatest(addr);
      await loadAddresses();
    } finally {
      setBusy(false);
    }
  }, [loadAddresses]);

  const copy = useCallback(async (value: string) => {
    await Clipboard.setStringAsync(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, []);

  return (
    <View style={styles.root}>
      <View style={styles.tabs}>
        <Pressable
          style={[styles.tab, tab === 'create' && styles.tabActive]}
          onPress={() => setTab('create')}
        >
          <Text style={[styles.tabText, tab === 'create' && styles.tabTextActive]}>Create</Text>
        </Pressable>
        <Pressable
          style={[styles.tab, tab === 'deposits' && styles.tabActive]}
          onPress={() => setTab('deposits')}
        >
          <Text style={[styles.tabText, tab === 'deposits' && styles.tabTextActive]}>Deposits</Text>
        </Pressable>
      </View>

      {tab === 'create' ? (
        <View style={styles.body}>
          <Pressable style={[styles.primary, busy && styles.dim]} onPress={create} disabled={busy}>
            {busy ? <ActivityIndicator color="#000" /> : <Text style={styles.primaryText}>Create burn address</Text>}
          </Pressable>

          {latest && (
            <View style={styles.card}>
              <Text style={styles.label}>New burn address</Text>
              <View style={styles.addrRow}>
                <Text style={styles.address} numberOfLines={1} ellipsizeMode="middle" selectable>
                  {latest}
                </Text>
                <Pressable style={styles.copyBtn} onPress={() => copy(latest)}>
                  <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
                </Pressable>
              </View>
            </View>
          )}

          <Text style={styles.section}>Your burn addresses</Text>
          <FlatList
            data={addresses}
            keyExtractor={(a) => a.address}
            renderItem={({ item }) => (
              <View style={styles.row}>
                <Text style={styles.address} numberOfLines={1} ellipsizeMode="middle" selectable>
                  {item.address}
                </Text>
                <Pressable style={styles.copyBtn} onPress={() => copy(item.address)}>
                  <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
                </Pressable>
              </View>
            )}
            ListEmptyComponent={<Text style={styles.empty}>No burn addresses yet.</Text>}
          />
        </View>
      ) : (
        <FlatList
          style={styles.body}
          data={deposits}
          keyExtractor={(d) => d.leaf}
          renderItem={({ item }) => (
            <View style={styles.row}>
              <View style={{ flex: 1 }}>
                <Text style={styles.rowTitle}>Deposit</Text>
                <Text style={styles.address} numberOfLines={1} ellipsizeMode="middle">
                  {item.leaf}
                </Text>
              </View>
            </View>
          )}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={async () => {
                setRefreshing(true);
                await loadDeposits();
                setRefreshing(false);
              }}
              tintColor="#bbb"
            />
          }
          ListEmptyComponent={<Text style={styles.empty}>No deposits yet.</Text>}
          contentContainerStyle={deposits.length === 0 && styles.emptyContainer}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingTop: 64 },
  tabs: {
    flexDirection: 'row',
    marginHorizontal: 16,
    backgroundColor: '#1a1a1e',
    borderRadius: 12,
    padding: 4,
    marginBottom: 16,
  },
  tab: { flex: 1, paddingVertical: 10, alignItems: 'center', borderRadius: 9 },
  tabActive: { backgroundColor: '#e8e6e3' },
  tabText: { color: '#888', fontSize: 14, fontWeight: '600' },
  tabTextActive: { color: '#000' },
  body: { flex: 1, paddingHorizontal: 16 },
  primary: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  primaryText: { color: '#000', fontSize: 15, fontWeight: '600' },
  card: { marginTop: 16, marginBottom: 8 },
  label: { color: '#888', fontSize: 13, marginBottom: 6 },
  addrRow: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 10,
    gap: 12,
  },
  address: { color: '#eee', fontSize: 13, flex: 1 },
  rowTitle: { color: '#eee', fontSize: 15, fontWeight: '600' },
  amount: { color: '#7dd88f', fontSize: 15, fontWeight: '700' },
  copyBtn: {
    backgroundColor: '#e8e6e3',
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 14,
  },
  copyText: { color: '#000', fontSize: 13, fontWeight: '600' },
  section: { color: '#888', fontSize: 13, marginTop: 20, marginBottom: 10 },
  empty: { color: '#666', textAlign: 'center' },
  emptyContainer: { flexGrow: 1, justifyContent: 'center' },
  dim: { opacity: 0.6 },
});
