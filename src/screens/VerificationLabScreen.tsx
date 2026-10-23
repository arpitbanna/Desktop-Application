import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  TouchableOpacity
} from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';
import { ActionButton } from '../components/ActionButton';
import { HexViewer } from '../components/HexViewer';
import { packageService, TamperType } from '../services/packageService';
import {
  RECIPIENT_PRIMARY_TEST,
  TEST_ONLY_RECIPIENT_PRIVATE_KEYS
} from '../services/recipientKeys';
import { SAMPLE_ASSETS } from '../assets/sampleAssets';
import { fromBase64 } from '../utils/cryptoUtils';
import { DecryptionVerificationResult, EncryptedPackage } from '../types/security';

interface VerificationLabScreenProps {
  route?: any;
}

export const VerificationLabScreen: React.FC<VerificationLabScreenProps> = ({ route }) => {
  const [activePackage, setActivePackage] = useState<EncryptedPackage | null>(null);
  const [originalSha256, setOriginalSha256] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<DecryptionVerificationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [tamperApplied, setTamperApplied] = useState<string | null>(null);

  // If a package was passed via navigation, load it
  useEffect(() => {
    if (route?.params?.preloadedPackage) {
      setActivePackage(route.params.preloadedPackage);
      setOriginalSha256(route.params.originalSha256 || route.params.preloadedPackage.payloadSha256);
      setVerificationResult(null);
      setTamperApplied(null);
    } else if (!activePackage) {
      // Auto-generate a test package for initial verification lab state
      generateInitialTestPackage();
    }
  }, [route?.params]);

  const generateInitialTestPackage = async () => {
    setLoading(true);
    try {
      const asset = SAMPLE_ASSETS[0];
      const payloadBytes = fromBase64(asset.dataBase64);
      const res = await packageService.encryptPayload({
        payloadBytes,
        payloadType: asset.type,
        recipient: RECIPIENT_PRIMARY_TEST
      });
      setActivePackage(res.package);
      setOriginalSha256(res.package.payloadSha256);
      setVerificationResult(null);
      setTamperApplied(null);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAndDecrypt = async () => {
    if (!activePackage) return;
    setLoading(true);
    try {
      const recipientPrivKey = TEST_ONLY_RECIPIENT_PRIVATE_KEYS[activePackage.recipientKeyId];
      if (!recipientPrivKey) {
        throw new Error(`Test recipient private key not found for ID: ${activePackage.recipientKeyId}`);
      }

      const result = await packageService.verifyAndDecryptPackage({
        pkg: activePackage,
        recipientPrivateKeyPem: recipientPrivKey,
        expectedOriginalSha256: originalSha256 || undefined
      });

      setVerificationResult(result);
      if (result.isVerified) {
        Alert.alert('Verification PASSED', `All cryptographic integrity checks passed.\nElapsed: ${result.elapsedMs}ms\nSignature: VALID\nGCM Tag: VALID\nPayload Match: EXACT`);
      } else {
        Alert.alert('Tampering Detected', `Cryptographic failure: ${result.tamperReason}`);
      }
    } catch (err: any) {
      Alert.alert('Verification Error', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApplyTampering = (type: TamperType, label: string) => {
    if (!activePackage) return;
    const tampered = packageService.createTamperedPackage(activePackage, type);
    setActivePackage(tampered);
    setTamperApplied(label);
    setVerificationResult(null);
    Alert.alert('Tamper Applied', `${label} applied to test package copy. Tap "Verify & Decrypt" to test tamper rejection.`);
  };

  const handleResetPackage = () => {
    generateInitialTestPackage();
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Test Recipient Disclosure Notice */}
      <View style={styles.disclosure}>
        <Text style={styles.disclosureTitle}>TEST RECIPIENT ENVIRONMENT</Text>
        <Text style={styles.disclosureText}>
          In production, recipient private keys are strictly guarded inside authorized verifier data centers. The Verification Lab includes an isolated synthetic test key pair solely to demonstrate authenticated decryption and tampering rejection offline.
        </Text>
      </View>

      {/* Package Under Test */}
      {activePackage && (
        <CyberCard
          title="ENCRYPTED PACKAGE UNDER TEST"
          subtitle={`Package ID: ${activePackage.packageId}`}
          badge={
            tamperApplied ? (
              <SecurityBadge label="TAMPERED" variant="custom" />
            ) : (
              <SecurityBadge label="INTACT" variant="custom" />
            )
          }
          variant={tamperApplied ? 'danger' : 'default'}
        >
          <View style={styles.row}>
            <Text style={styles.label}>Recipient Target:</Text>
            <Text style={styles.val}>{activePackage.recipientKeyId}</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Device Origin Key:</Text>
            <Text style={styles.val}>{activePackage.deviceKeyId.slice(0, 16)}...</Text>
          </View>
          <View style={styles.row}>
            <Text style={styles.label}>Payload Type:</Text>
            <Text style={styles.val}>{activePackage.payloadType} ({activePackage.payloadSize} B)</Text>
          </View>

          <HexViewer label="Ciphertext Sample" value={activePackage.ciphertext} maxChars={60} />
          <HexViewer label="AES-GCM Auth Tag (128-bit)" value={activePackage.authenticationTag} />
          <HexViewer label="Device Hardware Signature" value={activePackage.deviceSignature} maxChars={60} />

          <ActionButton
            title="Verify Integrity & Decrypt"
            onPress={handleVerifyAndDecrypt}
            loading={loading}
            variant="primary"
            style={{ marginTop: 12 }}
          />
        </CyberCard>
      )}

      {/* Verification Results Card */}
      {verificationResult && (
        <CyberCard
          title="VERIFICATION & DECRYPTION REPORT"
          subtitle={`Evaluated in ${verificationResult.elapsedMs}ms`}
          badge={
            <SecurityBadge
              label={verificationResult.isVerified ? 'VERIFIED' : 'REJECTED'}
              variant="custom"
            />
          }
          variant={verificationResult.isVerified ? 'success' : 'danger'}
        >
          <View style={styles.resultRow}>
            <Text style={styles.label}>Device Signature Status:</Text>
            <Text style={[styles.val, verificationResult.signatureValid ? styles.valSuccess : styles.valDanger]}>
              {verificationResult.signatureValid ? 'VALID (MATCHED)' : 'INVALID / TAMPERED'}
            </Text>
          </View>

          <View style={styles.resultRow}>
            <Text style={styles.label}>AES-GCM Tag Integrity:</Text>
            <Text style={[styles.val, verificationResult.gcmTagValid ? styles.valSuccess : styles.valDanger]}>
              {verificationResult.gcmTagValid ? 'AUTHENTICATED' : 'TAG MISMATCH / MODIFIED'}
            </Text>
          </View>

          <View style={styles.resultRow}>
            <Text style={styles.label}>Payload SHA-256 Match:</Text>
            <Text style={[styles.val, verificationResult.payloadMatch ? styles.valSuccess : styles.valDanger]}>
              {verificationResult.payloadMatch ? 'EXACT MATCH' : 'HASH MISMATCH'}
            </Text>
          </View>

          {verificationResult.tamperReason && (
            <View style={styles.errorBox}>
              <Text style={styles.errorTitle}>CRYPTOGRAPHIC REJECTION REASON:</Text>
              <Text style={styles.errorText}>{verificationResult.tamperReason}</Text>
            </View>
          )}

          {verificationResult.recoveredPayloadSha256 && (
            <HexViewer
              label="Recovered Payload SHA-256"
              value={verificationResult.recoveredPayloadSha256}
              highlight={verificationResult.payloadMatch}
            />
          )}
        </CyberCard>
      )}

      {/* Tamper Demonstration Suite */}
      <CyberCard
        title="TAMPER TESTING LABORATORY"
        subtitle="Simulate deliberate adversary tampering and observe rejection"
      >
        <Text style={styles.tamperIntro}>
          Tap any button to inject a cryptographic flaw into this package copy. Then verify that authenticated decryption or signature verification immediately rejects the payload.
        </Text>

        <ActionButton
          title="Tamper Ciphertext (Flip Bits)"
          onPress={() => handleApplyTampering('MODIFY_CIPHERTEXT', 'Corrupted Ciphertext')}
          variant="secondary"
        />

        <ActionButton
          title="Tamper Authentication Tag"
          onPress={() => handleApplyTampering('MODIFY_AUTH_TAG', 'Corrupted GCM Tag')}
          variant="secondary"
        />

        <ActionButton
          title="Tamper Header AAD Metadata"
          onPress={() => handleApplyTampering('MODIFY_AAD_METADATA', 'Corrupted AAD Metadata')}
          variant="secondary"
        />

        <ActionButton
          title="Tamper Device Signature"
          onPress={() => handleApplyTampering('MODIFY_SIGNATURE', 'Corrupted Hardware Signature')}
          variant="secondary"
        />

        <ActionButton
          title="Reset to Fresh Intact Package"
          onPress={handleResetPackage}
          variant="primary"
          style={{ marginTop: 8 }}
        />
      </CyberCard>
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
  disclosure: {
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    borderWidth: 1,
    borderColor: colors.accent,
    borderRadius: 8,
    padding: 12,
    marginBottom: 16
  },
  disclosureTitle: {
    fontSize: 11,
    fontWeight: '800',
    color: colors.accent,
    letterSpacing: 0.8,
    marginBottom: 4
  },
  disclosureText: {
    fontSize: 11,
    color: colors.textSecondary,
    lineHeight: 16
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder
  },
  resultRow: {
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
    fontWeight: '700',
    color: colors.textPrimary
  },
  valSuccess: {
    color: colors.success
  },
  valDanger: {
    color: colors.danger
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: colors.danger,
    borderRadius: 8,
    padding: 10,
    marginVertical: 10
  },
  errorTitle: {
    fontSize: 11,
    fontWeight: '800',
    color: colors.danger,
    marginBottom: 4
  },
  errorText: {
    fontSize: 12,
    color: colors.textPrimary,
    lineHeight: 16
  },
  tamperIntro: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 16,
    marginBottom: 10
  }
});
