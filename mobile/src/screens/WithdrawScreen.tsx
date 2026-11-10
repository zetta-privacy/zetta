import { useCallback, useEffect, useState } from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';

import { allLeafIndices } from '../discovery';
import { getOrCreateSecretKey, listBurnAddresses } from '../burn';
import { pirRead } from '../pirClient';
import { buildWithdrawInput } from '../withdraw';
import { proveWithdraw } from '../prove';
import { formatUsd } from '../format';
import { submitWithdraw } from '../submit'
import { CHAIN_ID } from '../tokens'
import { getOrCreateWallet } from '../eth'

const VALUES_LEVEL = 33;

interface Transfer {
  address: string;    // burn address
  index: number;      // address index i
  leafIndex: number;
  value: bigint;
}

function bytesToBigIntBE(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function WithdrawScreen() {
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const secretKey = await getOrCreateSecretKey();
    const addresses = await listBurnAddresses();
    const all: Transfer[] = [];
    for (const a of addresses) {
      for (const leafIndex of await allLeafIndices(a.address)) {
        const value = bytesToBigIntBE(await pirRead(leafIndex, VALUES_LEVEL));
        all.push({ address: a.address, index: a.index, leafIndex, value });
      }
    }
    all.sort((a, b) => a.leafIndex - b.leafIndex);
    setTransfers(all);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const withdraw = useCallback(async () => {
    if (transfers.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const w = await getOrCreateWallet();
      const secretKey = await getOrCreateSecretKey();
      const transfers4 = transfers.slice(0, 4).map((t) => ({ index: t.index, leafIndex: t.leafIndex }));
      const input = await buildWithdrawInput(CHAIN_ID, w.address, secretKey, transfers4);
      const { proof, publicSignals } = await proveWithdraw(input);
      const hash = await submitWithdraw(w.privateKey, CHAIN_ID, w.address, proof, publicSignals);
      console.log('withdraw tx', hash);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [transfers]);


  return (
    <View style={styles.root}>
      <Text style={styles.section}>Burn transfers</Text>
      <FlatList
        data={transfers}
        keyExtractor={(t) => `${t.address}-${t.leafIndex}`}
        renderItem={({ item }) => (
          <View style={styles.row}>
            <Text style={styles.idx}>{item.leafIndex}</Text>
            <Text style={styles.addr} numberOfLines={1} ellipsizeMode="middle">
              {item.address}
            </Text>
            <Text style={styles.amount}>{formatUsd(item.value)}</Text>
          </View>
        )}
        ListEmptyComponent={<Text style={styles.empty}>No transfers.</Text>}
      />
      {error && <Text style={styles.error}>{error}</Text>}
      <Pressable
        style={[styles.button, (busy || transfers.length === 0) && styles.dim]}
        onPress={withdraw}
        disabled={busy || transfers.length === 0}
      >
        <Text style={styles.buttonText}>
          {busy ? 'Proving…' : 'Withdraw first 4'}
        </Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  section: { color: '#888', fontSize: 13, marginBottom: 10 },
  row: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: '#1a1a1e', borderRadius: 10,
    padding: 14, marginBottom: 10, gap: 12,
  },
  idx: { color: '#5b9dff', fontSize: 13, width: 40 },
  addr: { color: '#eee', fontSize: 13, flex: 1 },
  amount: { color: '#7dd88f', fontSize: 15, fontWeight: '700' },
  button: {
    backgroundColor: '#e8e6e3', borderRadius: 12,
    paddingVertical: 14, alignItems: 'center', marginTop: 12,
  },
  buttonText: { color: '#000', fontSize: 15, fontWeight: '600' },
  empty: { color: '#666', textAlign: 'center', marginTop: 24 },
  error: { color: '#ff7a7a', fontSize: 13, marginTop: 8 },
  dim: { opacity: 0.5 },
});
