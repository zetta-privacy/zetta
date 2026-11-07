import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useState } from 'react';
import { FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from 'react-native';

import { getOrCreateWallet, tokenBalance } from '../eth';
import { formatUsd } from '../format';
import { RPC_URL, TOKENS } from '../tokens';

interface Balance {
  id: string;
  name: string;
  symbol: string;
  amountWei: bigint | null;
}

export function HomeScreen() {
  const [address, setAddress] = useState<string | null>(null);
  const [balances, setBalances] = useState<Balance[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);

  const reload = useCallback(async () => {
    const w = await getOrCreateWallet();
    setAddress(w.address);
    setBalances(
      await Promise.all(
        TOKENS.map(async (t) => {
          try {
            return { ...t, amountWei: await tokenBalance(RPC_URL, t.address, w.address) };
          } catch (e) {
            console.warn(`balance ${t.symbol} failed`, e);
            return { ...t, amountWei: null };
          }
        }),
      ),
    );
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const copyAddress = useCallback(async () => {
    if (!address) return;
    await Clipboard.setStringAsync(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [address]);

  return (
    <View style={styles.root}>
      <Text style={styles.addressLabel}>Wallet</Text>
      <View style={styles.addressRow}>
        <Text style={styles.address} numberOfLines={1} ellipsizeMode="middle" selectable>
          {address ?? '—'}
        </Text>
        {address && (
          <Pressable
            style={({ pressed }) => [styles.copyBtn, pressed && styles.dim]}
            onPress={copyAddress}
          >
            <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
          </Pressable>
        )}
      </View>

      <Text style={styles.section}>Balances</Text>
      <FlatList
        data={balances}
        keyExtractor={(t) => t.id}
        renderItem={({ item }) => (
          <View style={styles.row}>
            <View style={{ flex: 1 }}>
              <Text style={styles.rowTitle}>{item.name}</Text>
              <Text style={styles.rowSub}>{item.symbol}</Text>
            </View>
            <Text style={styles.amount}>
              {item.amountWei == null ? '—' : formatUsd(item.amountWei)}
            </Text>
          </View>
        )}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={async () => {
              setRefreshing(true);
              await reload();
              setRefreshing(false);
            }}
            tintColor="#bbb"
          />
        }
        contentContainerStyle={balances.length === 0 && styles.emptyContainer}
        ListEmptyComponent={<Text style={styles.empty}>Loading balances…</Text>}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  addressLabel: { color: '#888', fontSize: 13 },
  addressRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginTop: 4,
  },
  address: { color: '#eee', fontSize: 14, flex: 1 },
  copyBtn: {
    backgroundColor: '#e8e6e3',
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 14,
  },
  copyText: { color: '#000', fontSize: 13, fontWeight: '600' },
  section: { color: '#888', fontSize: 13, marginTop: 28, marginBottom: 10 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 10,
  },
  rowTitle: { color: '#eee', fontSize: 15, fontWeight: '600' },
  rowSub: { color: '#888', fontSize: 12, marginTop: 4 },
  amount: { color: '#eee', fontSize: 15, fontWeight: '700' },
  emptyContainer: { flexGrow: 1, justifyContent: 'center' },
  empty: { color: '#666', textAlign: 'center' },
  dim: { opacity: 0.6 },
});
