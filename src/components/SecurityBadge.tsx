import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { colors } from '../theme/colors';
import { HardwareSecurityLevel, KeyLifecycleStatus } from '../types/security';

interface SecurityBadgeProps {
  level?: HardwareSecurityLevel;
  status?: KeyLifecycleStatus;
  label?: string;
  variant?: 'level' | 'status' | 'custom';
}

export const SecurityBadge: React.FC<SecurityBadgeProps> = ({
  level,
  status,
  label,
  variant = 'level'
}) => {
  let badgeColor = colors.primary;
  let badgeBg = colors.primaryGlow;
  let text = label || '';

  if (variant === 'level' && level) {
    switch (level) {
      case 'STRONGBOX':
        badgeColor = colors.success;
        badgeBg = colors.successBg;
        text = 'STRONGBOX HSM';
        break;
      case 'TRUSTED_ENVIRONMENT':
        badgeColor = colors.primary;
        badgeBg = colors.primaryGlow;
        text = 'TEE TRUSTZONE';
        break;
      case 'SECURE_ENCLAVE':
        badgeColor = colors.accent;
        badgeBg = colors.accentGlow;
        text = 'SECURE ENCLAVE';
        break;
      case 'SOFTWARE_BACKED':
        badgeColor = colors.warning;
        badgeBg = colors.warningBg;
        text = 'SOFTWARE KEYSTORE';
        break;
      case 'SOFTWARE_SIMULATED':
        badgeColor = colors.warning;
        badgeBg = colors.warningBg;
        text = 'SIMULATOR (NON-HW)';
        break;
    }
  } else if (variant === 'status' && status) {
    switch (status) {
      case 'ACTIVE':
        badgeColor = colors.success;
        badgeBg = colors.successBg;
        text = 'ACTIVE';
        break;
      case 'EXPIRED':
        badgeColor = colors.warning;
        badgeBg = colors.warningBg;
        text = 'EXPIRED';
        break;
      case 'REVOKED':
        badgeColor = colors.danger;
        badgeBg = colors.dangerBg;
        text = 'LOCALLY REVOKED';
        break;
      case 'DELETED':
        badgeColor = colors.textMuted;
        badgeBg = 'rgba(107, 114, 128, 0.2)';
        text = 'DELETED';
        break;
    }
  }

  return (
    <View style={[styles.badge, { backgroundColor: badgeBg, borderColor: badgeColor }]}>
      <View style={[styles.dot, { backgroundColor: badgeColor }]} />
      <Text style={[styles.text, { color: badgeColor }]}>{text}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
    borderWidth: 1
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    marginRight: 6
  },
  text: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8
  }
});
