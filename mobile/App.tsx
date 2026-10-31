import { Ionicons } from '@expo/vector-icons';
import { BlurView } from 'expo-blur';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { CardsScreen } from './src/screens/CardsScreen';
import { HomeScreen } from './src/screens/HomeScreen';
import { SettingsScreen } from './src/screens/SettingsScreen';
import { getOrCreateIdentitySecret } from './src/storage';
import { LockScreen } from './src/screens/LockScreen'

type Tab = 'home' | 'cards' | 'settings';

const TABS: {
  id: Tab;
  label: string;
  icon: keyof typeof Ionicons.glyphMap;
  iconActive: keyof typeof Ionicons.glyphMap;
}[] = [
  { id: 'home', label: 'Home', icon: 'home-outline', iconActive: 'home' },
  { id: 'cards', label: 'Cards', icon: 'card-outline', iconActive: 'card' },
  { id: 'settings', label: 'Settings', icon: 'settings-outline', iconActive: 'settings' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('home');
  const [locked, setLocked] = useState(true);

  // create the wallet's signing key once, on first launch
  useEffect(() => {
    getOrCreateIdentitySecret().catch(() => {});
  }, []);

  if (locked) return <LockScreen onUnlock={() => setLocked(false)} />;

  return (
    <View style={styles.root}>
      <StatusBar style="light" />

      {/* conditional mount ⇒ each screen reloads its data on tab switch */}
      {tab === 'home' && <HomeScreen />}
      {tab === 'cards' && <CardsScreen />}
      {tab === 'settings' && <SettingsScreen />}

      {/* floating frosted-glass tab bar */}
      <View style={styles.tabBarWrap} pointerEvents="box-none">
        <BlurView intensity={50} tint="dark" style={styles.tabBar}>
          {TABS.map((t) => {
            const active = tab === t.id;
            return (
              <Pressable key={t.id} style={styles.tabItem} onPress={() => setTab(t.id)}>
                <Ionicons
                  name={active ? t.iconActive : t.icon}
                  size={22}
                  color={active ? '#fff' : 'rgba(255,255,255,0.45)'}
                />
                <Text style={[styles.tabLabel, active && styles.tabLabelActive]}>
                  {t.label}
                </Text>
              </Pressable>
            );
          })}
        </BlurView>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0e0e10' },
  tabBarWrap: { position: 'absolute', left: 16, right: 16, bottom: 24 },
  tabBar: {
    flexDirection: 'row',
    borderRadius: 24,
    overflow: 'hidden', // clips the blur to the pill shape
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: 'rgba(255,255,255,0.08)',
  },
  tabItem: { flex: 1, alignItems: 'center', paddingVertical: 10 },
  tabLabel: { color: 'rgba(255,255,255,0.45)', fontSize: 11, marginTop: 3 },
  tabLabelActive: { color: '#fff', fontWeight: '600' },
});
