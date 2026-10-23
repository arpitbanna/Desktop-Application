/**
 * Mock for react-native in Node/Jest test environment
 */

export const Platform = {
  OS: 'node',
  select: (obj: any) => obj.default || obj.ios || obj.android
};

export const NativeModules: Record<string, any> = {};

export default {
  Platform,
  NativeModules
};
