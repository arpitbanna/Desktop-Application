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
import { diagnosticsService, SelfTestResult } from '../services/diagnosticsService';
import { lifecycleService } from '../services/lifecycleService';
import { AuditEvent, PlatformDiagnostics } from '../types/security';

export const DiagnosticsScreen: React.FC = () => {
  const [diagnostics, setDiagnostics] = useState<PlatformDiagnostics | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [selfTest, setSelfTest] = useState<SelfTestResult | null>(null);
  const [exportedReport, setExportedReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [testLoading, setTestLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const diag = await diagnosticsService.getDiagnostics();
      setDiagnostics(diag);
      setAuditLogs(lifecycleService.getAuditLogs());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunSelfTest = async () => {
    setTestLoading(true);
    try {
      const res = await diagnosticsService.runSelfTest();
      setSelfTest(res);
      await loadData();
      Alert.alert(
        res.passed ? 'Self-Test PASSED' : 'Self-Test FAILED',
        `Cryptographic self-test status: ${res.passed ? '100% OPERATIONAL' : 'ERROR'}\nEncryption: ${res.encryptionElapsedMs}ms\nDecryption: ${res.decryptionElapsedMs}ms`
      );
    } catch (err: any) {
      Alert.alert('Error', err.message);
    } finally {
      setTestLoading(false);
    }
  };

  const handleExportReport = async () => {
    try {
      const report = await diagnosticsService.exportSanitizedDiagnosticReport();
      setExportedReport(report);
      Alert.alert('Diagnostics Exported', 'Sanitized JSON diagnostic report generated (zero secrets or private keys).');
    } catch (err: any) {
      Alert.alert('Export Error', err.message);
    }
  };

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={loading} onRefresh={loadData} tintColor={colors.primary} />}
    >
      {/* Platform Capabilities */}
      <CyberCard
        title="PLATFORM SECURITY SPECIFICATION"
        subtitle="Detected hardware cryptoprocessor capabilities"
        badge={
          diagnostics ? (
            <SecurityBadge level={diagnostics.detectedSecurityLevel} />
          ) : undefined
        }
      >
        {diagnostics && (
          <>
            <View style={styles.row}>
              <Text style={styles.label}>Platform / Runtime:</Text>
              <Text style={styles.val}>{diagnostics.platform.toUpperCase()} ({diagnostics.osVersion})</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Device Model:</Text>
              <Text style={styles.val}>{diagnostics.deviceModel}</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>StrongBox Keymaster:</Text>
              <Text style={[styles.val, diagnostics.strongBoxAvailable ? styles.valSuccess : styles.valWarning]}>
                {diagnostics.strongBoxAvailable ? 'SUPPORTED' : 'UNAVAILABLE'}
              </Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>TEE (TrustZone):</Text>
              <Text style={[styles.val, diagnostics.teeAvailable ? styles.valSuccess : styles.valWarning]}>
                {diagnostics.teeAvailable ? 'SUPPORTED' : 'NOT DETECTED'}
              </Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Apple Secure Enclave:</Text>
              <Text style={[styles.val, diagnostics.secureEnclaveAvailable ? styles.valSuccess : styles.valWarning]}>
                {diagnostics.secureEnclaveAvailable ? 'SUPPORTED' : 'NOT DETECTED'}
              </Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Hardware Key Attestation:</Text>
              <Text style={[styles.val, diagnostics.keyAttestationSupported ? styles.valSuccess : styles.valWarning]}>
                {diagnostics.keyAttestationSupported ? 'SUPPORTED' : 'UNSUPPORTED'}
              </Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Offline Architecture:</Text>
              <Text style={[styles.val, styles.valSuccess]}>100% ZERO-NETWORK</Text>
            </View>
          </>
        )}
      </CyberCard>

      {/* Interactive Cryptographic Benchmark */}
      <CyberCard
        title="OFFLINE INTEGRITY SELF-TEST"
        subtitle="Benchmark hybrid encryption, signature, and tamper rejection"
      >
        <ActionButton
          title="Run Cryptographic Self-Test"
          onPress={handleRunSelfTest}
          loading={testLoading}
          variant="primary"
        />

        {selfTest && (
          <View style={styles.testResultBox}>
            <View style={styles.row}>
              <Text style={styles.label}>Self-Test Result:</Text>
              <Text style={[styles.val, selfTest.passed ? styles.valSuccess : styles.valDanger]}>
                {selfTest.passed ? 'PASSED (100% OPERATIONAL)' : 'FAILED'}
              </Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Key Generation Time:</Text>
              <Text style={styles.val}>{selfTest.keyGenerationElapsedMs} ms</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Hybrid Encryption Time:</Text>
              <Text style={styles.val}>{selfTest.encryptionElapsedMs} ms</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Decryption & Verification:</Text>
              <Text style={styles.val}>{selfTest.decryptionElapsedMs} ms</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>Tamper Detection Status:</Text>
              <Text style={[styles.val, selfTest.tamperDetectionPassed ? styles.valSuccess : styles.valDanger]}>
                {selfTest.tamperDetectionPassed ? 'CONFIRMED' : 'FAILED'}
              </Text>
            </View>
          </View>
        )}
      </CyberCard>

      {/* Audit Log Stream */}
      <CyberCard
        title="SANITIZED AUDIT LOG"
        subtitle="Chronological record of cryptographic events (Zero secrets logged)"
        badge={<SecurityBadge label={`${auditLogs.length} EVENTS`} variant="custom" />}
      >
        {auditLogs.length > 0 ? (
          auditLogs.slice(0, 10).map(log => (
            <View key={log.id} style={styles.logItem}>
              <View style={styles.logHeader}>
                <Text style={styles.logAction}>{log.action}</Text>
                <Text style={[styles.logStatus, log.status === 'SUCCESS' ? styles.valSuccess : log.status === 'WARNING' ? styles.valWarning : styles.valDanger]}>
                  {log.status}
                </Text>
              </View>
              <Text style={styles.logDetails}>{log.details}</Text>
              <Text style={styles.logTime}>{log.timestamp.replace('T', ' ').slice(0, 19)} UTC</Text>
            </View>
          ))
        ) : (
          <Text style={styles.emptyText}>No audit events logged yet.</Text>
        )}

        <ActionButton
          title="Export Sanitized Diagnostics JSON"
          onPress={handleExportReport}
          variant="secondary"
          style={{ marginTop: 12 }}
        />
      </CyberCard>

      {/* Exported JSON Preview */}
      {exportedReport && (
        <CyberCard title="SANITIZED REPORT JSON" subtitle="Safe diagnostic dump">
          <HexViewer label="Report Output (No secrets)" value={exportedReport} maxChars={150} />
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
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 5,
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
  valWarning: {
    color: colors.warning
  },
  valDanger: {
    color: colors.danger
  },
  testResultBox: {
    marginTop: 10,
    backgroundColor: colors.monoBg,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    padding: 10
  },
  logItem: {
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder,
    paddingVertical: 8
  },
  logHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 2
  },
  logAction: {
    fontSize: 12,
    fontWeight: '700',
    color: colors.textPrimary
  },
  logStatus: {
    fontSize: 11,
    fontWeight: '700'
  },
  logDetails: {
    fontSize: 11,
    color: colors.textSecondary,
    lineHeight: 15
  },
  logTime: {
    fontSize: 10,
    color: colors.textMuted,
    marginTop: 3
  },
  emptyText: {
    fontSize: 12,
    color: colors.textMuted
  }
});
