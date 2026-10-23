import React from 'react';
import {
  TouchableOpacity,
  Text,
  ActivityIndicator,
  StyleSheet,
  ViewStyle,
  TextStyle
} from 'react-native';
import { colors } from '../theme/colors';

interface ActionButtonProps {
  title: string;
  onPress: () => void;
  loading?: boolean;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'danger' | 'success';
  style?: ViewStyle;
  textStyle?: TextStyle;
  icon?: React.ReactNode;
}

export const ActionButton: React.FC<ActionButtonProps> = ({
  title,
  onPress,
  loading = false,
  disabled = false,
  variant = 'primary',
  style,
  textStyle,
  icon
}) => {
  const getBackgroundColor = () => {
    if (disabled) return colors.cardBorder;
    switch (variant) {
      case 'secondary':
        return colors.cardBackground;
      case 'danger':
        return colors.danger;
      case 'success':
        return colors.success;
      default:
        return colors.primary;
    }
  };

  const getTextColor = () => {
    if (disabled) return colors.textMuted;
    if (variant === 'secondary') return colors.textPrimary;
    return '#0B0F17'; // High contrast dark text on bright buttons
  };

  const getBorderColor = () => {
    if (variant === 'secondary') return colors.primary;
    return 'transparent';
  };

  return (
    <TouchableOpacity
      activeOpacity={0.8}
      onPress={onPress}
      disabled={disabled || loading}
      style={[
        styles.button,
        {
          backgroundColor: getBackgroundColor(),
          borderColor: getBorderColor()
        },
        style
      ]}
    >
      {loading ? (
        <ActivityIndicator color={getTextColor()} size="small" />
      ) : (
        <>
          {icon}
          <Text
            style={[
              styles.text,
              { color: getTextColor(), marginLeft: icon ? 8 : 0 },
              textStyle
            ]}
          >
            {title}
          </Text>
        </>
      )}
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  button: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    marginVertical: 6
  },
  text: {
    fontSize: 14,
    fontWeight: '700',
    letterSpacing: 0.5
  }
});
