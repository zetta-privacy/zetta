import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import {
  bytesToHex,
  getOrCreateWallet,
  privateKeyFromMnemonic,
  setMnemonic,
} from '../eth';
import { authenticate } from '../lock';

export function SettingsScreen() {
  const [address, setAddress] = useState<string | null>(null);
  const [mnemonic, setMnemonicState] = useState<string | null>(null);

  const [revealedMnemonic, setRevealedMnemonic] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [importOpen, setImportOpen] = useState(false);
  const [importValue, setImportValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [imported, setImported] = useState(false);

  const refresh = useCallback(async () => {
    const w = await getOrCreateWallet();
    setAddress(w.address);
    setMnemonicState(w.mnemonic);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const copy = useCallback(async (value: string) => {
    await Clipboard.setStringAsync(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, []);

  const exportMnemonic = useCallback(async () => {
    if (!(await authenticate())) return;
    setRevealedMnemonic(mnemonic);
  }, [mnemonic]);

  const exportKey = useCallback(async () => {
    if (!(await authenticate())) return;
    if (!mnemonic) return;
    setRevealedKey(`0x${bytesToHex(privateKeyFromMnemonic(mnemonic))}`);
  }, [mnemonic]);

  const openImport = useCallback(async () => {
    if (!(await authenticate())) return;
    setImportOpen(true);
    setImported(false);
    setError(null);
  }, []);

  const restore = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await setMnemonic(importValue);
      setImportValue('');
      setImported(true);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [importValue, refresh]);

  return (
    <View style={styles.root}>
      <Text style={styles.section}>Address</Text>
      <View style={styles.card}>
        <Text style={styles.value} numberOfLines={1} ellipsizeMode="middle" selectable>
          {address ?? '—'}
        </Text>
        {address && (
          <Pressable
            style={({ pressed }) => [styles.copyBtn, pressed && styles.dim]}
            onPress={() => copy(address)}
          >
            <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
          </Pressable>
        )}
      </View>

      <Text style={styles.section}>Backup &amp; recovery</Text>

      {revealedMnemonic ? (
        <View style={styles.secretCard}>
          <Text style={styles.mnemonic} selectable>{revealedMnemonic}</Text>
          <Pressable
            style={({ pressed }) => [styles.copyBtn, pressed && styles.dim]}
            onPress={() => copy(revealedMnemonic)}
          >
            <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
          </Pressable>
        </View>
      ) : (
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.dim]} onPress={exportMnemonic}>
          <Text style={styles.btnText}>Export mnemonic (12 words)</Text>
        </Pressable>
      )}

      {revealedKey ? (
        <View style={styles.secretCard}>
          <Text style={styles.mnemonic} numberOfLines={1} ellipsizeMode="middle" selectable>
            {revealedKey}
          </Text>
          <Pressable
            style={({ pressed }) => [styles.copyBtn, pressed && styles.dim]}
            onPress={() => copy(revealedKey)}
          >
            <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
          </Pressable>
        </View>
      ) : (
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.dim]} onPress={exportKey}>
          <Text style={styles.btnText}>Export private key</Text>
        </Pressable>
      )}

      {(revealedMnemonic || revealedKey) && (
        <Text style={styles.warn}>
          Anyone with the mnemonic or private key controls your funds. Never share it or
          store it on a connected device.
        </Text>
      )}

      {importOpen ? (
        <View style={styles.importBlock}>
          <TextInput
            style={styles.input}
            value={importValue}
            onChangeText={setImportValue}
            placeholder="Paste 12-word mnemonic"
            placeholderTextColor="#555"
            multiline
            autoCapitalize="none"
            autoCorrect={false}
            editable={!busy}
          />
          {imported && <Text style={styles.ok}>Wallet restored.</Text>}
          {error && <Text style={styles.error}>{error}</Text>}
          <Pressable
            style={({ pressed }) => [styles.btn, (busy || pressed) && styles.dim]}
            onPress={restore}
            disabled={busy}
          >
            {busy ? <ActivityIndicator color="#000" /> : <Text style={styles.btnText}>Restore</Text>}
          </Pressable>
        </View>
      ) : (
        <Pressable style={({ pressed }) => [styles.btnOutline, pressed && styles.dim]} onPress={openImport}>
          <Text style={styles.btnOutlineText}>Import mnemonic</Text>
        </Pressable>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  section: { color: '#888', fontSize: 13, marginBottom: 10 },
  card: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 28,
    gap: 12,
  },
  value: { color: '#eee', fontSize: 13, flex: 1 },
  copyBtn: {
    backgroundColor: '#e8e6e3',
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 14,
  },
  copyText: { color: '#000', fontSize: 13, fontWeight: '600' },
  secretCard: {
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 12,
    gap: 12,
  },
  mnemonic: { color: '#eee', fontSize: 15, lineHeight: 24 },
  btn: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginBottom: 12,
  },
  btnText: { color: '#000', fontSize: 15, fontWeight: '600' },
  btnOutline: {
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#3a3a40',
  },
  btnOutlineText: { color: '#eee', fontSize: 15, fontWeight: '600' },
  warn: { color: '#b8902a', fontSize: 12, lineHeight: 18, marginBottom: 20 },
  importBlock: { marginTop: 20 },
  input: {
    backgroundColor: '#1f1f24',
    borderRadius: 10,
    padding: 14,
    color: '#eee',
    fontSize: 15,
    lineHeight: 22,
    marginBottom: 12,
    minHeight: 80,
  },
  ok: { color: '#7dd88f', fontSize: 13, marginBottom: 8 },
  error: { color: '#ff7a7a', fontSize: 13, marginBottom: 8 },
  dim: { opacity: 0.6 },
});
