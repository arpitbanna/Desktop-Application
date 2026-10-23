import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  TouchableOpacity,
  RefreshControl
} from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';
import { ActionButton } from '../components/ActionButton';
import { HexViewer } from '../components/HexViewer';
import { lifecycleService, KeyRotationRecord, RevocationEntry } from '../services/lifecycleService';
import { securityService } from '../services/securityService';
import { DeviceKeyMetadata } from '../types/security';

export const KeyLifecycleScreen: React.FC = () => {
  const [managedKeys, setManagedKeys] = useState<DeviceKeyMetadata[]>([]);
  const [rotationHistory, setRotationHistory] = useState<KeyRotationRecord[]>([]);
  const [revocationList, setRevocationList] = useState<RevocationEntry[]>([]);
  const [loading, setLoading] = useState(false);

  const loadLifecycleData = async () => {
    setLoading(true);
    try {
      const keys = lifecycleService.getManagedKeys();
      setManagedKeys(keys);
      setRotationHistory(lifecycleService.getRotationHistory());
      setRevocationList(lifecycleService.getRevocationList());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLifecycleData();
  }, []);

  const handleRevokeKey = (keyId: string) => {
    Alert.alert(
      'Locally Revoke Key',
      `Are you sure you want to revoke key '${keyId}'? Once revoked, the application policy will strictly reject this key for any signing or encryption operations.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Revoke Key',
          style: 'destructive',
          onPress: async () => {
            await lifecycleService.revokeKeyLocally(keyId, 'User initiated local revocation test');
            Alert.alert('Key Revoked', `Key ${keyId} is now marked as locally REVOKED.`);
            loadLifecycleData();
          }
        }
      ]
    );
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={loading} onRefresh={loadLifecycleData} tintColor={colors.primary} />}
    >
      {/* Offline Revocation Reality Notice */}
      <View style={styles.notice}>
        <Text style={styles.noticeTitle}>OFFLINE REVOCATION REALITY</Text>
        <Text style={styles.noticeText}>
          A device in airplane mode enforces locally recorded revocation rules and expiry policies. Learning about newly revoked keys issued globally requires an online CRL or trust update.
        </Text>
      </View>

      {/* Managed Keys List */}
      <CyberCard
        title="MANAGED DEVICE KEYS"
        subtitle="Hardware and local registry lifecycle states"
        badge={<SecurityBadge label={`${managedKeys.length} KEYS`} variant="custom" />}
      >
        {managedKeys.length > 0 ? (
          managedKeys.map(k => (
            <View key={k.keyId} style={styles.keyCard}>
              <View style={styles.keyHeader}>
                <Text style={styles.aliasText}>{k.alias}</Text>
                <SecurityBadge status={k.status} variant="status" />
              </View>

              <HexViewer label="Key ID Fingerprint" value={k.keyId} />

              <View style={styles.row}>
                <Text style={styles.label}>Expires:</Text>
                <Text style={styles.val}>{k.expiresAt.slice(0, 10)}</Text>
              </View>

              <View style={styles.row}>
                <Text style={styles.label}>Hardware Protection:</Text>
                <Text style={styles.val}>{k.securityLevel}</Text>
              </View>

              {k.status === 'ACTIVE' && (
                <ActionButton
                  title="Revoke This Key Locally"
                  onPress={() => handleRevokeKey(k.keyId)}
                  variant="danger"
                  style={{ marginTop: 8 }}
                />
              )}
            </View>
          ))
        ) : (
          <Text style={styles.emptyText}>No managed keys in registry. Generate a key from the Dashboard.</Text>
        )}
      </CyberCard>

      {/* Key Rotation History */}
      <CyberCard
        title="KEY ROTATION TIMELINE"
        subtitle="Chronological audit of retired and fresh keys"
        badge={<SecurityBadge label={`${rotationHistory.length} ROTATIONS`} variant="custom" />}
      >
        {rotationHistory.length > 0 ? (
          rotationHistory.map((rot, idx) => (
            <View key={idx} style={styles.historyItem}>
              <View style={styles.timelineDot} />
              <View style={styles.historyContent}>
                <Text style={styles.rotDate}>{rot.rotatedAt.replace('T', ' ').slice(0, 19)} UTC</Text>
                <Text style={styles.rotDetails}>Old: {rot.oldAlias} ({rot.oldKeyId.slice(0, 12)}...)</Text>
                <Text style={[styles.rotDetails, { color: colors.primary }]}>
                  New: {rot.newAlias} ({rot.newKeyId.slice(0, 12)}...)
                </Text>
              </View>
            </View>
          ))
        ) : (
          <Text style={styles.emptyText}>No key rotations recorded in current session.</Text>
        )}
      </CyberCard>

      {/* Local Revocation Registry */}
      <CyberCard
        title="LOCAL REVOCATION REGISTRY"
        subtitle="Locally blacklisted keys rejected by security policy"
        badge={<SecurityBadge label={`${revocationList.length} REVOKED`} variant="custom" />}
      >
        {revocationList.length > 0 ? (
          revocationList.map(entry => (
            <View key={entry.keyId} style={styles.revokedItem}>
              <HexViewer label="Revoked Key ID" value={entry.keyId} />
              <Text style={styles.revDate}>Revoked at: {entry.revokedAt.replace('T', ' ').slice(0, 19)} UTC</Text>
              <Text style={styles.revReason}>Reason: {entry.reason}</Text>
            </View>
          ))
        ) : (
          <Text style={styles.emptyText}>Zero locally revoked keys. All active keys remain valid.</Text>
        )}
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
  notice: {
    backgroundColor: 'rgba(245, 158, 11, 0.08)',
    borderWidth: 1,
    borderColor: colors.warning,
    borderRadius: 8,
    padding: 12,
    marginBottom: 16
  },
  noticeTitle: {
    fontSize: 11,
    fontWeight: '800',
    color: colors.warning,
    letterSpacing: 0.8,
    marginBottom: 4
  },
  noticeText: {
    fontSize: 11,
    color: colors.textSecondary,
    lineHeight: 16
  },
  keyCard: {
    backgroundColor: colors.monoBg,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    borderRadius: 8,
    padding: 12,
    marginBottom: 10
  },
  keyHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  aliasText: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.textPrimary
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 3
  },
  label: {
    fontSize: 11,
    color: colors.textSecondary
  },
  val: {
    fontSize: 11,
    fontWeight: '600',
    color: colors.textPrimary
  },
  emptyText: {
    fontSize: 12,
    color: colors.textMuted,
    lineHeight: 18
  },
  historyItem: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 12
  },
  timelineDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: colors.primary,
    marginTop: 4,
    marginRight: 10
  },
  historyContent: {
    flex: 1
  },
  rotDate: {
    fontSize: 11,
    color: colors.textMuted
  },
  rotDetails: {
    fontSize: 12,
    color: colors.textSecondary,
    marginTop: 2
  },
  revokedItem: {
    backgroundColor: 'rgba(239, 68, 68, 0.06)',
    borderWidth: 1,
    borderColor: colors.danger,
    borderRadius: 8,
    padding: 10,
    marginBottom: 8
  },
  revDate: {
    fontSize: 10,
    color: colors.textMuted,
    marginTop: 4
  },
  revReason: {
    fontSize: 11,
    color: colors.danger,
    marginTop: 2
  }
});
