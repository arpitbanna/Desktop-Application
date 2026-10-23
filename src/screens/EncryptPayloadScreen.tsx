import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert
} from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';
import { ActionButton } from '../components/ActionButton';
import { HexViewer } from '../components/HexViewer';
import { SAMPLE_ASSETS, SampleAsset } from '../assets/sampleAssets';
import { AVAILABLE_RECIPIENTS } from '../services/recipientKeys';
import { packageService } from '../services/packageService';
import { fromBase64 } from '../utils/cryptoUtils';
import { EncryptedPackage, RecipientKeyInfo } from '../types/security';

interface EncryptPayloadScreenProps {
  navigation: any;
}

export const EncryptPayloadScreen: React.FC<EncryptPayloadScreenProps> = ({ navigation }) => {
  const [selectedAsset, setSelectedAsset] = useState<SampleAsset>(SAMPLE_ASSETS[0]);
  const [selectedRecipient, setSelectedRecipient] = useState<RecipientKeyInfo>(AVAILABLE_RECIPIENTS[0]);
  const [loading, setLoading] = useState(false);
  const [encryptedPackage, setEncryptedPackage] = useState<EncryptedPackage | null>(null);
  const [encryptionLatency, setEncryptionLatency] = useState<number | null>(null);

  const handleEncrypt = async () => {
    setLoading(true);
    try {
      const payloadBytes = fromBase64(selectedAsset.dataBase64);
      const result = await packageService.encryptPayload({
        payloadBytes,
        payloadType: selectedAsset.type,
        recipient: selectedRecipient
      });

      setEncryptedPackage(result.package);
      setEncryptionLatency(result.elapsedMs);
      Alert.alert(
        'Payload Encrypted',
        `Package ID: ${result.package.packageId}\nElapsed: ${result.elapsedMs}ms\nAES-256-GCM + RSA-OAEP-SHA256`
      );
    } catch (err: any) {
      Alert.alert('Encryption Failed', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenInLab = () => {
    if (!encryptedPackage) return;
    navigation.navigate('Verify', {
      preloadedPackage: encryptedPackage,
      originalSha256: encryptedPackage.payloadSha256
    });
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Step 1: Select Payload */}
      <CyberCard
        title="1. SELECT LOCAL SAMPLE PAYLOAD"
        subtitle="Binary data / images stored locally on device (Offline)"
      >
        <Text style={styles.sectionHelp}>
          Choose synthetic test payload to encrypt. Zero external network calls.
        </Text>

        {SAMPLE_ASSETS.map(asset => {
          const isSelected = asset.id === selectedAsset.id;
          return (
            <TouchableOpacity
              key={asset.id}
              activeOpacity={0.8}
              onPress={() => setSelectedAsset(asset)}
              style={[
                styles.assetOption,
                isSelected && styles.assetOptionSelected
              ]}
            >
              <View style={styles.assetHeader}>
                <Text style={[styles.assetName, isSelected && { color: colors.primary }]}>
                  {asset.name}
                </Text>
                <Text style={styles.assetSize}>{asset.sizeBytes} bytes</Text>
              </View>
              <Text style={styles.assetDesc}>{asset.description}</Text>
            </TouchableOpacity>
          );
        })}

        <View style={styles.selectedAssetDetails}>
          <Text style={styles.detailLabel}>Active Payload:</Text>
          <Text style={styles.detailVal}>{selectedAsset.name} ({selectedAsset.type})</Text>
        </View>
      </CyberCard>

      {/* Step 2: Select Recipient Key */}
      <CyberCard
        title="2. CHOOSE RECIPIENT PUBLIC KEY"
        subtitle="Target recipient whose public key wraps the ephemeral AES session key"
      >
        {AVAILABLE_RECIPIENTS.map(rcpt => {
          const isSelected = rcpt.keyId === selectedRecipient.keyId;
          return (
            <TouchableOpacity
              key={rcpt.keyId}
              activeOpacity={0.8}
              onPress={() => setSelectedRecipient(rcpt)}
              style={[
                styles.assetOption,
                isSelected && styles.assetOptionSelected
              ]}
            >
              <View style={styles.assetHeader}>
                <Text style={[styles.assetName, isSelected && { color: colors.primary }]}>
                  {rcpt.label}
                </Text>
                <SecurityBadge label="TEST ONLY" variant="custom" />
              </View>
              <Text style={styles.assetDesc}>{rcpt.organization}</Text>
              <HexViewer label="Recipient Key Fingerprint" value={rcpt.fingerprintSha256} />
            </TouchableOpacity>
          );
        })}
      </CyberCard>

      {/* Step 3: Hybrid Cryptographic Workflow Notice */}
      <CyberCard
        title="3. HYBRID ENCRYPTION PROTOCOL"
        subtitle="Cryptographic parameters applied per payload"
      >
        <View style={styles.paramRow}>
          <Text style={styles.paramName}>Bulk Encryption:</Text>
          <Text style={styles.paramVal}>AES-256-GCM (Fresh key per payload)</Text>
        </View>
        <View style={styles.paramRow}>
          <Text style={styles.paramName}>Nonce / IV:</Text>
          <Text style={styles.paramVal}>96-bit Unique Nonce (CSPRNG)</Text>
        </View>
        <View style={styles.paramRow}>
          <Text style={styles.paramName}>Authenticated Data:</Text>
          <Text style={styles.paramVal}>Package Header JSON (AAD)</Text>
        </View>
        <View style={styles.paramRow}>
          <Text style={styles.paramName}>Key Wrapping:</Text>
          <Text style={styles.paramVal}>RSA-OAEP with SHA-256 & MGF1</Text>
        </View>
        <View style={styles.paramRow}>
          <Text style={styles.paramName}>Hardware Signature:</Text>
          <Text style={styles.paramVal}>Device Identity Key over Canonical Digest</Text>
        </View>

        <ActionButton
          title="Start Hybrid Encryption"
          onPress={handleEncrypt}
          loading={loading}
          variant="primary"
          style={{ marginTop: 12 }}
        />
      </CyberCard>

      {/* Step 4: Results */}
      {encryptedPackage && (
        <CyberCard
          title="ENCRYPTED PACKAGE GENERATED"
          subtitle={`Encryption completed in ${encryptionLatency}ms`}
          badge={<SecurityBadge label="ENCRYPTED" variant="custom" />}
          variant="success"
        >
          <HexViewer label="Package ID" value={encryptedPackage.packageId} highlight />
          <HexViewer label="Payload SHA-256 (Original)" value={encryptedPackage.payloadSha256} />
          <HexViewer label="AES-GCM Nonce (Base64)" value={encryptedPackage.nonce} />
          <HexViewer label="128-bit Authentication Tag (Base64)" value={encryptedPackage.authenticationTag} />
          <HexViewer label="Wrapped AES Key (RSA-OAEP Base64)" value={encryptedPackage.wrappedAesKey} maxChars={80} />
          <HexViewer label="Ciphertext (Base64 Sample)" value={encryptedPackage.ciphertext} maxChars={80} />
          <HexViewer label="Device Hardware Signature (Base64)" value={encryptedPackage.deviceSignature} maxChars={80} />

          <ActionButton
            title="Open in Verification & Tamper Lab"
            onPress={handleOpenInLab}
            variant="secondary"
            style={{ marginTop: 10 }}
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
  sectionHelp: {
    fontSize: 12,
    color: colors.textSecondary,
    marginBottom: 10
  },
  assetOption: {
    backgroundColor: colors.monoBg,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    borderRadius: 8,
    padding: 12,
    marginBottom: 8
  },
  assetOptionSelected: {
    borderColor: colors.primary,
    backgroundColor: 'rgba(6, 182, 212, 0.08)'
  },
  assetHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4
  },
  assetName: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.textPrimary
  },
  assetSize: {
    fontSize: 11,
    color: colors.textMuted
  },
  assetDesc: {
    fontSize: 11,
    color: colors.textSecondary,
    lineHeight: 15
  },
  selectedAssetDetails: {
    flexDirection: 'row',
    marginTop: 6,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: colors.codeBorder
  },
  detailLabel: {
    fontSize: 12,
    color: colors.textMuted,
    marginRight: 6
  },
  detailVal: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.textPrimary
  },
  paramRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 5,
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder
  },
  paramName: {
    fontSize: 12,
    color: colors.textSecondary
  },
  paramVal: {
    fontSize: 12,
    fontWeight: '600',
    color: colors.textPrimary
  }
});
