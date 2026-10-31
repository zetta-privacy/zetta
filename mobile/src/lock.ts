import * as LocalAuthentication from 'expo-local-authentication';

export async function authenticate(): Promise<boolean> {
  const r = await LocalAuthentication.authenticateAsync({
    promptMessage: 'Unlock Zetta',
    cancelLabel: 'Cancel',
    disableDeviceFallback: false, // <-- lets the OS fall back to the device passcode
  });
  return r.success;
}
