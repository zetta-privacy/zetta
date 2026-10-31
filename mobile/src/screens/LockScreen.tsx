import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { authenticate } from '../lock';

export function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    (async () => {
      if (await authenticate()) onUnlock();
      else setFailed(true);
    })();
  }, []);

  return (
    <View style={styles.root}>
      <Text style={styles.logo}>Z</Text>
      {failed && (
        <Pressable style={styles.button} onPress={async () => {
          if (await authenticate()) onUnlock();
        }}>
          <Text style={styles.buttonText}>Unlock</Text>
        </Pressable>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, alignItems: 'center', justifyContent: 'center', backgroundColor: '#0e0e10' },
  logo: { color: '#fff', fontSize: 48, fontWeight: '700' },
  button: { marginTop: 32, backgroundColor: '#fff', borderRadius: 12, paddingHorizontal: 48, paddingVertical: 16 },
  buttonText: { color: '#000', fontWeight: '600', fontSize: 16 },
});
