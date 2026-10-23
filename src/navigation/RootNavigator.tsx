import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { NavigationContainer } from '@react-navigation/native';
import { colors } from '../theme/colors';

// Screens
import { DashboardScreen } from '../screens/DashboardScreen';
import { DeviceIdentityScreen } from '../screens/DeviceIdentityScreen';
import { EncryptPayloadScreen } from '../screens/EncryptPayloadScreen';
import { VerificationLabScreen } from '../screens/VerificationLabScreen';
import { KeyLifecycleScreen } from '../screens/KeyLifecycleScreen';
import { DiagnosticsScreen } from '../screens/DiagnosticsScreen';
import { AboutScreen } from '../screens/AboutScreen';

const Tab = createBottomTabNavigator();

// Minimal, reliable tab bar icon renderer using unicode cybersecurity glyphs
const TabGlyph: React.FC<{ symbol: string; focused: boolean }> = ({ symbol, focused }) => (
  <View style={[styles.glyphContainer, focused && styles.glyphFocused]}>
    <Text style={[styles.glyphText, focused && styles.glyphTextFocused]}>{symbol}</Text>
  </View>
);

export const RootNavigator: React.FC = () => {
  return (
    <NavigationContainer>
      <Tab.Navigator
        screenOptions={{
          headerStyle: {
            backgroundColor: colors.background,
            borderBottomColor: colors.codeBorder,
            borderBottomWidth: 1,
            elevation: 0,
            shadowOpacity: 0
          },
          headerTitleStyle: {
            color: colors.textPrimary,
            fontSize: 16,
            fontWeight: '700',
            letterSpacing: 0.5
          },
          headerTintColor: colors.primary,
          tabBarStyle: {
            backgroundColor: colors.background,
            borderTopColor: colors.codeBorder,
            borderTopWidth: 1,
            paddingBottom: 4,
            paddingTop: 4,
            height: 60
          },
          tabBarActiveTintColor: colors.primary,
          tabBarInactiveTintColor: colors.textMuted,
          tabBarLabelStyle: {
            fontSize: 10,
            fontWeight: '600',
            letterSpacing: 0.2
          }
        }}
      >
        <Tab.Screen
          name="Dashboard"
          component={DashboardScreen}
          options={{
            title: 'TrustRoot',
            tabBarLabel: 'Status',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="🛡️" focused={focused} />
          }}
        />
        <Tab.Screen
          name="Identity"
          component={DeviceIdentityScreen}
          options={{
            title: 'Device Identity',
            tabBarLabel: 'Identity',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="🔑" focused={focused} />
          }}
        />
        <Tab.Screen
          name="Encrypt"
          component={EncryptPayloadScreen}
          options={{
            title: 'Encrypt Payload',
            tabBarLabel: 'Encrypt',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="🔒" focused={focused} />
          }}
        />
        <Tab.Screen
          name="Verify"
          component={VerificationLabScreen}
          options={{
            title: 'Verification Lab',
            tabBarLabel: 'Lab',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="🧪" focused={focused} />
          }}
        />
        <Tab.Screen
          name="Lifecycle"
          component={KeyLifecycleScreen}
          options={{
            title: 'Key Lifecycle',
            tabBarLabel: 'Lifecycle',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="🔄" focused={focused} />
          }}
        />
        <Tab.Screen
          name="Diagnostics"
          component={DiagnosticsScreen}
          options={{
            title: 'Security Diagnostics',
            tabBarLabel: 'Diagnostics',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="📊" focused={focused} />
          }}
        />
        <Tab.Screen
          name="About"
          component={AboutScreen}
          options={{
            title: 'Security Architecture',
            tabBarLabel: 'About',
            tabBarIcon: ({ focused }) => <TabGlyph symbol="ℹ️" focused={focused} />
          }}
        />
      </Tab.Navigator>
    </NavigationContainer>
  );
};

const styles = StyleSheet.create({
  glyphContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 28,
    height: 24,
    borderRadius: 6
  },
  glyphFocused: {
    backgroundColor: 'rgba(6, 182, 212, 0.12)'
  },
  glyphText: {
    fontSize: 14,
    opacity: 0.6
  },
  glyphTextFocused: {
    opacity: 1
  }
});
