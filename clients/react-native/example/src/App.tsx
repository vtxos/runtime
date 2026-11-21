import { useState } from 'react';
import {
  Button,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import {
  Enclave,
  type Pins,
  type SessionLike,
} from '@vtxos/react-native-wallet';

// Hermes has it; React Native's types don't declare it.
declare function atob(data: string): string;

/** What `cargo run -p vtxos-uniffi --example dev_enclave` prints, decoded. */
type Settings = {
  enclaveUrl: string;
  pins: {
    trustRootPem: string;
    pcr0: string;
    pcr16: string;
    maxAgeSecs: number;
  };
};

function decodeSettings(line: string): Settings {
  const base64 = line.trim().replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')));
}

/**
 * A stand-in for a passkey's PRF output, which is what makes the key in an app. For a dev enclave
 * only: Math.random is no source for a real key.
 */
function devPrfOutput(): ArrayBuffer {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes.buffer;
}

function describe(e: unknown): string {
  const err = e as { tag?: string; inner?: { message?: string }; message?: string };
  return err.tag ? `${err.tag}: ${err.inner?.message ?? ''}` : String(err.message ?? e);
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(text: string): ArrayBuffer {
  const clean = text.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

/**
 * The library carries calls as bytes and holds the phone's half of the key. What a call's bytes
 * mean is the app's, which knows the policy its enclave runs. So this example knows none: it
 * registers a key, opens a session, and sends whatever bytes it is given to whatever method it is
 * given.
 */
export default function App() {
  const [settings, setSettings] = useState('');
  const [session, setSession] = useState<SessionLike>();
  const [method, setMethod] = useState('/cosigner.v1.Cosigner/GetServerInfo');
  const [request, setRequest] = useState('');
  const [reply, setReply] = useState('');
  const [status, setStatus] = useState('Paste the dev enclave’s line.');

  async function run(what: string, step: () => Promise<string>) {
    setStatus(`${what}…`);
    try {
      setStatus(await step());
    } catch (e) {
      setStatus(`${what} failed: ${describe(e)}`);
    }
  }

  const register = () =>
    run('Registering', async () => {
      const s = decodeSettings(settings);
      const pins: Pins = {
        trustRootPem: s.pins.trustRootPem,
        pcr0: s.pins.pcr0,
        pcr16: s.pins.pcr16,
        maxAgeSecs: BigInt(s.pins.maxAgeSecs),
      };
      const enclave = new Enclave(s.enclaveUrl, pins);
      const prf = devPrfOutput();
      const record = await enclave.register(prf);
      setSession(enclave.open(record, prf));
      return `Registered tenant ${record.tenantId}`;
    });

  const call = () =>
    run('Calling', async () => {
      const answer = await session!.call(method.trim(), fromHex(request));
      setReply(hex(answer));
      return `${method.trim()} answered ${answer.byteLength} bytes`;
    });

  return (
    <View style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text testID="status" style={styles.status}>
          {status}
        </Text>
        {session === undefined ? (
          <>
            <TextInput
              testID="settings"
              style={styles.input}
              placeholder="Dev enclave settings"
              autoCapitalize="none"
              autoCorrect={false}
              value={settings}
              onChangeText={setSettings}
            />
            <Button testID="register" title="Register and open" onPress={register} />
          </>
        ) : (
          <>
            <TextInput
              testID="method"
              style={styles.input}
              placeholder="/package.Service/Method"
              autoCapitalize="none"
              autoCorrect={false}
              value={method}
              onChangeText={setMethod}
            />
            <TextInput
              testID="request"
              style={styles.input}
              placeholder="The request, as hex (empty for an empty message)"
              autoCapitalize="none"
              autoCorrect={false}
              value={request}
              onChangeText={setRequest}
            />
            <Button testID="call" title="Call" onPress={call} />
            <Text selectable testID="reply" style={styles.bytes}>
              {reply}
            </Text>
          </>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, paddingTop: 48 },
  content: { padding: 16, gap: 12 },
  status: { fontWeight: 'bold' },
  input: { borderWidth: 1, borderColor: '#888', padding: 8 },
  bytes: { fontFamily: 'monospace', fontSize: 12 },
});
