import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  TextInput
} from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';
import { ActionButton } from '../components/ActionButton';
import { HexViewer } from '../components/HexViewer';
import { securityService } from '../services/securityService';
import { DeviceKeyMetadata } from '../types/security';

export const DeviceIdentityScreen: React.FC = () => {
  const [keyMetadata, setKeyMetadata] = useState<DeviceKeyMetadata | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [challengeText, setChallengeText] = useState('TRUSTROOT-CHALLENGE-2026');
  const [signatureResult, setSignatureResult] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);

  const loadKey = async () => {
    setLoading(true);
    try {
      const key = await securityService.getActiveKeyMetadata();
      setKeyMetadata(key);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadKey();
  }, []);

  const handleRotateKey = async () => {
    Alert.alert(
      'Rotate Device Key',
      'This will generate a fresh key pair in secure hardware and archive the current key. Continue?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Rotate',
          onPress: async () => {
            setActionLoading(true);
            try {
              const newKey = await securityService.rotateDeviceKey('EC_P256', true);
              setKeyMetadata(newKey);
              setSignatureResult(null);
              setVerificationResult(null);
              Alert.alert('Key Rotated', `New Key ID: ${newKey.keyId}`);
            } catch (err: any) {
              Alert.alert('Rotation Error', err.message);
            } finally {
              setActionLoading(false);
            }
          }
        }
      ]
    );
  };

  const handleDeleteKey = async () => {
    Alert.alert(
      'Permanent Deletion Warning',
      'Deleting this device key from hardware keystore means no further device signatures can be produced with this identity. Previously encrypted data signed by this key cannot produce new verification signatures. Are you sure?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Permanently Delete',
          style: 'destructive',
          onPress: async () => {
            setActionLoading(true);
            try {
              await securityService.deleteDeviceKey();
              setKeyMetadata(null);
              setSignatureResult(null);
              setVerificationResult(null);
              Alert.alert('Deleted', 'Key deleted from platform keystore.');
            } catch (err: any) {
              Alert.alert('Deletion Error', err.message);
            } finally {
              setActionLoading(false);
            }
          }
        }
      ]
    );
  };

  const handleSignChallenge = async () => {
    if (!keyMetadata) return;
    setActionLoading(true);
    try {
      const sig = await securityService.signChallenge(challengeText);
      setSignatureResult(sig);

      // Verify signature live
      const isValid = await securityService.verifySignature(
        keyMetadata.publicKeyPem,
        challengeText,
        sig
      );
      setVerificationResult(isValid);
    } catch (err: any) {
      Alert.alert('Signing Error', err.message);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Non-Exportability Banner */}
      <View style={styles.banner}>
        <Text style={styles.bannerTitle}>NON-EXPORTABLE PRIVATE KEY</Text>
        <Text style={styles.bannerText}>
          Private key bytes reside exclusively within the platform's isolated security hardware. The operating system kernel and application memory cannot read or export private key bits.
        </Text>
      </View>

      {keyMetadata ? (
        <>
          <CyberCard
            title="DEVICE IDENTITY CREDENTIAL"
            subtitle="Platform-bound public key properties"
            badge={<SecurityBadge level={keyMetadata.securityLevel} />}
          >
            <HexViewer label="Key ID (SHA-256 Public Fingerprint)" value={keyMetadata.keyId} highlight />

            <View style={styles.row}>
              <Text style={styles.label}>Keystore Alias:</Text>
              <Text style={styles.val}>{keyMetadata.alias}</Text>
            </View>

            <View style={styles.row}>
              <Text style={styles.label}>Algorithm & Size:</Text>
              <Text style={styles.val}>{keyMetadata.algorithm} ({keyMetadata.keySize} bits)</Text>
            </View>

            <View style={styles.row}>
              <Text style={styles.label}>Creation Timestamp:</Text>
              <Text style={styles.val}>{keyMetadata.createdAt.slice(0, 19).replace('T', ' ')} UTC</Text>
            </View>

            <View style={styles.row}>
              <Text style={styles.label}>Expiration Timestamp:</Text>
              <Text style={styles.val}>{keyMetadata.expiresAt.slice(0, 19).replace('T', ' ')} UTC</Text>
            </View>

            <View style={styles.row}>
              <Text style={styles.label}>Hardware Attestation:</Text>
              <Text style={[styles.val, keyMetadata.attestationStatus.includes('VALID') ? styles.valSuccess : styles.valWarning]}>
                {keyMetadata.attestationStatus}
              </Text>
            </View>

            <View style={styles.row}>
              <Text style={styles.label}>Permitted Purposes:</Text>
              <Text style={styles.val}>{keyMetadata.purposes.join(', ')}</Text>
            </View>

            <HexViewer
              label="Public Key (X.509 SPKI PEM - Safe to Export)"
              value={keyMetadata.publicKeyPem}
              maxChars={120}
            />
          </CyberCard>

          {/* Hardware Signature Challenge Test */}
          <CyberCard
            title="SIGN LIVE CHALLENGE"
            subtitle="Verify private key execution inside secure hardware"
          >
            <Text style={styles.inputLabel}>Input Challenge / Nonce:</Text>
            <TextInput
              style={styles.input}
              value={challengeText}
              onChangeText={setChallengeText}
              placeholder="Enter challenge string"
              placeholderTextColor={colors.textMuted}
            />

            <ActionButton
              title="Sign with Hardware Key"
              onPress={handleSignChallenge}
              loading={actionLoading}
              variant="primary"
            />

            {signatureResult && (
              <View style={styles.signatureBox}>
                <HexViewer label="ECDSA Signature (DER Base64)" value={signatureResult} maxChars={80} />
                <View style={styles.row}>
                  <Text style={styles.label}>Public Key Verification:</Text>
                  <Text style={[styles.val, verificationResult ? styles.valSuccess : styles.valDanger]}>
                    {verificationResult ? 'VALID (MATCHED)' : 'SIGNATURE REJECTED'}
                  </Text>
                </View>
              </View>
            )}
          </CyberCard>

          {/* Key Lifecycle Management Actions */}
          <CyberCard title="IDENTITY ACTIONS" subtitle="Manage device key lifecycle">
            <ActionButton
              title="Rotate Key Pair"
              onPress={handleRotateKey}
              loading={actionLoading}
              variant="secondary"
            />
            <ActionButton
              title="Delete Device Key"
              onPress={handleDeleteKey}
              loading={actionLoading}
              variant="danger"
            />
          </CyberCard>
        </>
      ) : (
        <CyberCard title="NO ACTIVE DEVICE KEY" subtitle="Keystore is currently empty">
          <Text style={styles.emptyText}>
            No device identity key found in platform keystore. Generate one to establish the hardware root of trust.
          </Text>
          <ActionButton
            title="Generate Device Identity Key"
            onPress={async () => {
              setActionLoading(true);
              try {
                const k = await securityService.generateDeviceKey();
                setKeyMetadata(k);
              } catch (e: any) {
                Alert.alert('Error', e.message);
              } finally {
                setActionLoading(false);
              }
            }}
            loading={actionLoading}
            variant="primary"
          />
        </CyberCard>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  banner: {
    backgroundColor: 'rgba(6, 182, 212, 0.08)',
    borderWidth: 1,
    borderColor: colors.primary,
    borderRadius: 8,
    padding: 12,
    marginBottom: 16
  },
  bannerTitle: {
    fontSize: 12,
    fontWeight: '800',
    color: colors.primary,
    letterSpacing: 0.8,
    marginBottom: 4
  },
  bannerText: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 16
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder
  },
  label: {
    fontSize: 12,
    color: colors.textSecondary
  },
  val: {
    fontSize: 12,
    fontWeight: '600',
    color: colors.textPrimary
  },
  valSuccess: {
    color: colors.success
  },
  valWarning: {
    color: colors.warning
  },
  valDanger: {
    color: colors.danger
  },
  inputLabel: {
    fontSize: 12,
    color: colors.textSecondary,
    marginBottom: 6
  },
  input: {
    backgroundColor: colors.monoBg,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    borderRadius: 8,
    color: colors.textPrimary,
    padding: 10,
    fontSize: 13,
    marginBottom: 10
  },
  signatureBox: {
    marginTop: 10,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: colors.codeBorder
  },
  emptyText: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 18,
    marginBottom: 12
  }
});
