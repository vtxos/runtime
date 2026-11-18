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
  Vtxos,
  type Pins,
  type Vtxo,
  type WalletLike,
} from '@vtxos/react-native-wallet';

// Hermes has it; React Native's types don't declare it.
declare function atob(data: string): string;

/** What `cargo run -p vtxos-uniffi --example dev_enclave` prints, decoded. */
type Settings = {
  enclaveUrl: string;
  aspUrl: string;
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
 * A stand-in for a passkey's PRF output, which is what makes the wallet's key in an app. Regtest
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

export default function App() {
  const [settings, setSettings] = useState('');
  const [wallet, setWallet] = useState<WalletLike>();
  const [arkAddress, setArkAddress] = useState('');
  const [boardingAddress, setBoardingAddress] = useState('');
  const [balance, setBalance] = useState<bigint>();
  const [vtxos, setVtxos] = useState<Vtxo[]>([]);
  const [utxo, setUtxo] = useState('');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState('Paste the dev enclave’s line.');

  async function run(what: string, step: () => Promise<string>) {
    setStatus(`${what}…`);
    try {
      setStatus(await step());
    } catch (e) {
      setStatus(`${what} failed: ${describe(e)}`);
    }
  }

  async function show(w: WalletLike) {
    setBalance(await w.balance());
    setVtxos(await w.vtxos());
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
      const vtxosClient = new Vtxos(s.enclaveUrl, s.aspUrl, pins);
      const prf = devPrfOutput();
      const record = await vtxosClient.register(prf);
      const w = vtxosClient.open(record, prf);
      setWallet(w);
      setArkAddress(await w.arkAddress());
      setBoardingAddress(await w.boardingAddress());
      await show(w);
      return `Registered tenant ${record.tenantId}`;
    });

  const board = () =>
    run('Boarding', async () => {
      const [txid, vout, sats] = utxo.trim().split(':');
      const settled = await wallet!.board(
        { txid: txid!, vout: Number(vout), amountSats: BigInt(sats!) },
        undefined
      );
      await show(wallet!);
      return `Boarded ${settled.amountSats} sats in ${settled.commitmentTxid}`;
    });

  const send = () =>
    run('Sending', async () => {
      const sent = await wallet!.send(to.trim(), BigInt(amount), undefined);
      await show(wallet!);
      return `Sent in ${sent.arkTxid}`;
    });

  const refresh = () =>
    run('Refreshing', async () => {
      const settled = await wallet!.refresh(undefined);
      await show(wallet!);
      return `Refreshed into ${settled.vtxoTxid}:${settled.vtxoVout}`;
    });

  return (
    <View style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text testID="status" style={styles.status}>
          {status}
        </Text>
        {wallet === undefined ? (
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
            <Text selectable testID="ark-address">
              Ark: {arkAddress}
            </Text>
            <Text selectable testID="boarding-address">
              Boarding: {boardingAddress}
            </Text>
            <Text testID="balance">Balance: {balance?.toString()} sats</Text>
            {vtxos.map((v) => (
              <Text key={`${v.txid}:${v.vout}`} style={styles.vtxo}>
                {v.txid}:{v.vout} {v.amountSats.toString()} sats
              </Text>
            ))}
            <TextInput
              testID="utxo"
              style={styles.input}
              placeholder="txid:vout:sats paid to the boarding address"
              autoCapitalize="none"
              value={utxo}
              onChangeText={setUtxo}
            />
            <Button testID="board" title="Board" onPress={board} />
            <TextInput
              testID="to"
              style={styles.input}
              placeholder="Ark address to send to"
              autoCapitalize="none"
              value={to}
              onChangeText={setTo}
            />
            <TextInput
              testID="amount"
              style={styles.input}
              placeholder="sats"
              keyboardType="number-pad"
              value={amount}
              onChangeText={setAmount}
            />
            <Button testID="send" title="Send" onPress={send} />
            <Button testID="refresh" title="Refresh" onPress={refresh} />
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
  vtxo: { fontFamily: 'monospace', fontSize: 12 },
});
