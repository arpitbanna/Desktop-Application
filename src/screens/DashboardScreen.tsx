import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Alert
} from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';
import { ActionButton } from '../components/ActionButton';
import { HexViewer } from '../components/HexViewer';
import { securityService } from '../services/securityService';
import { diagnosticsService, SelfTestResult } from '../services/diagnosticsService';
import { DeviceKeyMetadata, PlatformDiagnostics } from '../types/security';

interface DashboardScreenProps {
  navigation: any;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({ navigation }) => {
  const [activeKey, setActiveKey] = useState<DeviceKeyMetadata | null>(null);
  const [diagnostics, setDiagnostics] = useState<PlatformDiagnostics | null>(null);
  const [lastSelfTest, setLastSelfTest] = useState<SelfTestResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    try {
      let key = await securityService.getActiveKeyMetadata();
      if (!key) {
        // Automatically initialize device identity key if not yet created
        key = await securityService.generateDeviceKey('trustroot_device_identity_v1', 'EC_P256', true);
      }
      setActiveKey(key);

      const diag = await diagnosticsService.getDiagnostics();
      setDiagnostics(diag);
    } catch (err: any) {
      console.error('Dashboard load error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerateFreshKey = async () => {
    setActionLoading(true);
    try {
      const key = await securityService.rotateDeviceKey('EC_P256', true);
      setActiveKey(key);
      Alert.alert('Key Generated', `Fresh device identity key initialized in secure keystore.\nKey ID: ${key.keyId}`);
      await loadData();
    } catch (err: any) {
      Alert.alert('Generation Error', err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunSelfTest = async () => {
    setActionLoading(true);
    try {
      const result = await diagnosticsService.runSelfTest();
      setLastSelfTest(result);
      Alert.alert(
        result.passed ? 'Self-Test PASSED' : 'Self-Test WARNING',
        `Verification: ${result.passed ? 'SUCCESS' : 'FAILED'}\nTamper Detection: ${result.tamperDetectionPassed ? 'CONFIRMED' : 'FAILED'}\nEncryption Latency: ${result.encryptionElapsedMs}ms\nDecryption Latency: ${result.decryptionElapsedMs}ms`
      );
    } catch (err: any) {
      Alert.alert('Self-Test Error', err.message);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={loading} onRefresh={loadData} tintColor={colors.primary} />}
    >
      {/* App Header Banner */}
      <View style={styles.header}>
        <View style={styles.headerTagRow}>
          <View style={styles.airplaneTag}>
            <View style={styles.greenPulse} />
            <Text style={styles.airplaneTagText}>AIRPLANE MODE READY — 100% OFFLINE</Text>
          </View>
        </View>
        <Text style={styles.headerTitle}>TrustRoot Mobile</Text>
        <Text style={styles.headerSubtitle}>Hardware-Backed Device Identity & Offline Data Protection</Text>
      </View>

      {/* Security Status Card */}
      <CyberCard
        title="DEVICE ROOT OF TRUST"
        subtitle="Keystore hardware status and active cryptographic binding"
        badge={
          activeKey ? (
            <SecurityBadge level={activeKey.securityLevel} />
          ) : (
            <SecurityBadge label="INITIALIZING..." variant="custom" />
          )
        }
        variant={activeKey?.isHardwareBacked ? 'highlight' : 'default'}
      >
        <View style={styles.statusRow}>
          <Text style={styles.label}>Hardware Protection:</Text>
          <Text style={[styles.val, activeKey?.isHardwareBacked ? styles.valSuccess : styles.valWarning]}>
            {activeKey?.isHardwareBacked ? 'Hardware Isolated (TEE/SE)' : 'Software Keystore (Simulated)'}
          </Text>
        </View>

        <View style={styles.statusRow}>
          <Text style={styles.label}>Private Key Exportability:</Text>
          <Text style={[styles.val, styles.valSuccess]}>
            STRICTLY NON-EXPORTABLE
          </Text>
        </View>

        <View style={styles.statusRow}>
          <Text style={styles.label}>Lifecycle State:</Text>
          <SecurityBadge status={activeKey?.status || 'ACTIVE'} variant="status" />
        </View>

        {activeKey && (
          <View style={styles.keyDetails}>
            <HexViewer label="Device Key Identifier (SHA-256 Fingerprint)" value={activeKey.keyId} highlight />
            <View style={styles.metaRow}>
              <Text style={styles.metaText}>Algorithm: {activeKey.algorithm}</Text>
              <Text style={styles.metaText}>Size: {activeKey.keySize} bits</Text>
            </View>
          </View>
        )}
      </CyberCard>

      {/* Quick Actions Grid */}
      <CyberCard title="QUICK SECURITY ACTIONS" subtitle="Execute hardware-backed operations">
        <ActionButton
          title="Encrypt Sample Payload"
          onPress={() => navigation.navigate('Encrypt')}
          variant="primary"
        />
        <ActionButton
          title="Open Verification & Tamper Lab"
          onPress={() => navigation.navigate('Verify')}
          variant="secondary"
        />
        <View style={styles.buttonRow}>
          <View style={{ flex: 1, marginRight: 6 }}>
            <ActionButton
              title="Rotate Key"
              onPress={handleGenerateFreshKey}
              loading={actionLoading}
              variant="secondary"
            />
          </View>
          <View style={{ flex: 1, marginLeft: 6 }}>
            <ActionButton
              title="Run Self-Test"
              onPress={handleRunSelfTest}
              loading={actionLoading}
              variant="secondary"
            />
          </View>
        </View>
      </CyberCard>

      {/* Last Security Test Card */}
      <CyberCard
        title="LOCAL SECURITY BENCHMARK"
        subtitle="Zero-backend cryptographic pipeline test"
        badge={
          lastSelfTest ? (
            <SecurityBadge
              label={lastSelfTest.passed ? 'PASSED' : 'CHECK FAILED'}
              variant="custom"
            />
          ) : (
            <SecurityBadge label="READY" variant="custom" />
          )
        }
      >
        <Text style={styles.bodyText}>
          {lastSelfTest
            ? `Self-test completed at ${lastSelfTest.timestamp.slice(11, 19)} UTC.\nEncryption: ${lastSelfTest.encryptionElapsedMs}ms | Decryption: ${lastSelfTest.decryptionElapsedMs}ms\nTamper detection: ${lastSelfTest.tamperDetectionPassed ? 'CONFIRMED' : 'FAILED'}`
            : 'No self-test run in current session. Tap "Run Self-Test" to benchmark hybrid encryption and tamper detection offline.'}
        </Text>
      </CyberCard>

      {/* Honest Disclosure Notice */}
      <View style={styles.noticeBox}>
        <Text style={styles.noticeTitle}>AUTHENTICITY COMMITMENT</Text>
        <Text style={styles.noticeText}>
          TrustRoot Mobile strictly reports detected hardware capabilities. We never display fake "100% secure" or "StrongBox" badges when running in software or simulator environments.
        </Text>
      </View>
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
  header: {
    marginBottom: 20,
    marginTop: 8
  },
  headerTagRow: {
    flexDirection: 'row',
    marginBottom: 8
  },
  airplaneTag: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderWidth: 1,
    borderColor: colors.success,
    borderRadius: 20,
    paddingHorizontal: 10,
    paddingVertical: 4
  },
  greenPulse: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: colors.success,
    marginRight: 6
  },
  airplaneTagText: {
    fontSize: 10,
    fontWeight: '800',
    color: colors.success,
    letterSpacing: 0.8
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: '800',
    color: colors.textPrimary,
    letterSpacing: 0.5
  },
  headerSubtitle: {
    fontSize: 13,
    color: colors.textSecondary,
    marginTop: 4
  },
  statusRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder
  },
  label: {
    fontSize: 13,
    color: colors.textSecondary
  },
  val: {
    fontSize: 13,
    fontWeight: '700'
  },
  valSuccess: {
    color: colors.success
  },
  valWarning: {
    color: colors.warning
  },
  keyDetails: {
    marginTop: 12
  },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 6
  },
  metaText: {
    fontSize: 11,
    color: colors.textMuted
  },
  buttonRow: {
    flexDirection: 'row',
    justifyContent: 'space-between'
  },
  bodyText: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 18
  },
  noticeBox: {
    backgroundColor: colors.monoBg,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    borderRadius: 8,
    padding: 12,
    marginTop: 8
  },
  noticeTitle: {
    fontSize: 11,
    fontWeight: '800',
    color: colors.primary,
    letterSpacing: 0.8,
    marginBottom: 4
  },
  noticeText: {
    fontSize: 11,
    color: colors.textMuted,
    lineHeight: 16
  }
});
