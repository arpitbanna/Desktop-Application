import React, { useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { colors, typography } from '../theme/colors';

interface HexViewerProps {
  label?: string;
  value: string;
  maxChars?: number;
  highlight?: boolean;
}

export const HexViewer: React.FC<HexViewerProps> = ({
  label,
  value,
  maxChars = 64,
  highlight = false
}) => {
  const [expanded, setExpanded] = useState(false);

  const displayValue = expanded || value.length <= maxChars
    ? value
    : `${value.slice(0, maxChars)}... (${value.length} chars)`;

  return (
    <View style={styles.container}>
      {label && <Text style={styles.label}>{label}</Text>}
      <TouchableOpacity
        activeOpacity={0.7}
        onPress={() => setExpanded(!expanded)}
        style={[
          styles.box,
          highlight && { borderColor: colors.primary, backgroundColor: 'rgba(6, 182, 212, 0.05)' }
        ]}
      >
        <Text style={[styles.text, highlight && { color: colors.primary }]}>
          {displayValue}
        </Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    marginVertical: 4
  },
  label: {
    fontSize: 12,
    fontWeight: '600',
    color: colors.textSecondary,
    marginBottom: 4
  },
  box: {
    backgroundColor: colors.monoBg,
    borderWidth: 1,
    borderColor: colors.codeBorder,
    borderRadius: 8,
    padding: 8
  },
  text: {
    fontFamily: typography.fontMono,
    fontSize: 11,
    color: colors.textPrimary,
    lineHeight: 16
  }
});
