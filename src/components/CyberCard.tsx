import React from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { colors } from '../theme/colors';

interface CyberCardProps {
  title?: string;
  subtitle?: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
  style?: ViewStyle;
  variant?: 'default' | 'highlight' | 'danger' | 'success';
}

export const CyberCard: React.FC<CyberCardProps> = ({
  title,
  subtitle,
  badge,
  children,
  style,
  variant = 'default'
}) => {
  const getBorderColor = () => {
    switch (variant) {
      case 'highlight':
        return colors.primary;
      case 'danger':
        return colors.danger;
      case 'success':
        return colors.success;
      default:
        return colors.cardBorder;
    }
  };

  return (
    <View style={[styles.card, { borderColor: getBorderColor() }, style]}>
      {(title || badge) && (
        <View style={styles.header}>
          <View style={styles.titleContainer}>
            {title && <Text style={styles.title}>{title}</Text>}
            {subtitle && <Text style={styles.subtitle}>{subtitle}</Text>}
          </View>
          {badge && <View style={styles.badgeContainer}>{badge}</View>}
        </View>
      )}
      <View style={styles.content}>{children}</View>
    </View>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.cardBackground,
    borderRadius: 12,
    borderWidth: 1,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 2
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: colors.codeBorder,
    paddingBottom: 8
  },
  titleContainer: {
    flex: 1,
    marginRight: 8
  },
  title: {
    fontSize: 16,
    fontWeight: '700',
    color: colors.textPrimary,
    letterSpacing: 0.5
  },
  subtitle: {
    fontSize: 12,
    color: colors.textSecondary,
    marginTop: 2
  },
  badgeContainer: {
    alignSelf: 'flex-start'
  },
  content: {
    // Content layout
  }
});
