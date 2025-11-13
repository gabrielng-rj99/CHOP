# React Native Migration TODO

## Current Status

The frontend is currently implemented in **React (web)** using:
- React with JavaScript
- Vite as build tool
- Inline CSS styling
- Running on port 8080

## Required Migration

The frontend should be migrated to **React Native** to support:
- Mobile apps (iOS and Android)
- Better native performance
- Mobile-specific UX patterns
- Offline-first capabilities

## Migration Plan

### 1. Setup React Native Project

```bash
npx react-native init ContractManagerMobile
# or
npx expo init ContractManagerMobile
```

**Decision needed:** Expo vs React Native CLI
- **Expo:** Easier, managed workflow, faster development
- **React Native CLI:** More control, custom native modules

### 2. Components to Migrate

All current pages need to be converted:
- ✅ Login (web implemented)
- ✅ Dashboard (web implemented)
- ✅ Clients (web implemented)
- ✅ Categories (web implemented)
- ✅ Users (web implemented - admin only)
- ✅ Contracts (web implemented)

### 3. Key Changes Required

#### Styling
- Convert inline CSS to StyleSheet.create()
- Replace HTML elements with React Native components:
  - `<div>` → `<View>`
  - `<input>` → `<TextInput>`
  - `<button>` → `<Button>` or `<TouchableOpacity>`
  - `<table>` → `<FlatList>` or custom component
  - `<select>` → `<Picker>` or modal selector

#### Navigation
- Replace React state-based routing with React Navigation
- Install: `@react-navigation/native`
- Implement Stack Navigator for main flow
- Drawer Navigator for menu

#### API Communication
- Keep fetch API (works in React Native)
- Add AsyncStorage for token persistence (replace localStorage)
- Handle network errors better for mobile

#### Forms
- Replace HTML forms with React Native forms
- Consider: react-hook-form or Formik for React Native

#### Modals
- Replace web modals with React Native Modal component
- Or use react-native-modal for enhanced features

### 4. Dependencies Needed

```json
{
  "dependencies": {
    "react": "18.x",
    "react-native": "0.73.x",
    "@react-navigation/native": "^6.x",
    "@react-navigation/stack": "^6.x",
    "@react-navigation/drawer": "^6.x",
    "react-native-gesture-handler": "^2.x",
    "react-native-reanimated": "^3.x",
    "react-native-screens": "^3.x",
    "react-native-safe-area-context": "^4.x",
    "@react-native-async-storage/async-storage": "^1.x"
  }
}
```

### 5. Architecture Considerations

#### State Management
- Current: useState/useEffect
- Consider: Context API or Zustand for mobile
- Keep it simple and performant

#### API Layer
- Create a dedicated API service layer
- Handle token refresh
- Implement retry logic for mobile network issues

#### Offline Support
- Consider: WatermelonDB or Realm for offline data
- Sync strategy when back online
- Queue API calls when offline

### 6. Platform-Specific Features

#### iOS
- Face ID / Touch ID for authentication
- Push notifications
- Share extension
- Background sync

#### Android
- Fingerprint authentication
- Push notifications
- Share intent
- Background services

### 7. Migration Steps

1. **Phase 1: Setup & Authentication**
   - Create React Native project
   - Implement login screen
   - Setup navigation structure
   - Implement AsyncStorage for tokens

2. **Phase 2: Core Features**
   - Migrate Clients page
   - Migrate Contracts page
   - Migrate Categories page

3. **Phase 3: Admin Features**
   - Migrate Users page (admin only)
   - Implement role-based access control

4. **Phase 4: Polish**
   - Add loading states
   - Error handling
   - Offline support
   - Push notifications

5. **Phase 5: Testing & Deployment**
   - Test on iOS devices
   - Test on Android devices
   - Setup CI/CD
   - Publish to stores

### 8. File Structure (Proposed)

```
ContractManagerMobile/
├── src/
│   ├── components/
│   │   ├── common/
│   │   │   ├── Button.js
│   │   │   ├── Input.js
│   │   │   ├── Card.js
│   │   │   └── Modal.js
│   │   └── ...
│   ├── screens/
│   │   ├── Auth/
│   │   │   └── LoginScreen.js
│   │   ├── Clients/
│   │   │   ├── ClientsListScreen.js
│   │   │   ├── ClientDetailsScreen.js
│   │   │   └── ClientFormScreen.js
│   │   ├── Contracts/
│   │   │   ├── ContractsListScreen.js
│   │   │   ├── ContractDetailsScreen.js
│   │   │   └── ContractFormScreen.js
│   │   ├── Categories/
│   │   │   └── CategoriesScreen.js
│   │   └── Users/
│   │       └── UsersScreen.js
│   ├── navigation/
│   │   ├── AppNavigator.js
│   │   └── DrawerNavigator.js
│   ├── services/
│   │   ├── api.js
│   │   ├── auth.js
│   │   └── storage.js
│   ├── utils/
│   │   ├── validators.js
│   │   └── formatters.js
│   └── constants/
│       ├── colors.js
│       └── config.js
├── android/
├── ios/
└── package.json
```

### 9. Design Considerations

#### Colors (from web)
```javascript
export const colors = {
  primary: '#3498db',
  success: '#27ae60',
  warning: '#f39c12',
  danger: '#e74c3c',
  info: '#9b59b6',
  gray: '#95a5a6',
  darkGray: '#2c3e50',
  lightGray: '#ecf0f1',
};
```

#### Typography
```javascript
export const typography = {
  h1: { fontSize: 32, fontWeight: 'bold' },
  h2: { fontSize: 24, fontWeight: 'bold' },
  h3: { fontSize: 18, fontWeight: '600' },
  body: { fontSize: 14 },
  caption: { fontSize: 12, color: '#7f8c8d' },
};
```

### 10. Testing Strategy

- Unit tests: Jest (included with React Native)
- Component tests: React Native Testing Library
- E2E tests: Detox or Appium
- API tests: Keep backend tests as is

### 11. Deployment

#### iOS
- Apple Developer Account required ($99/year)
- TestFlight for beta testing
- App Store submission

#### Android
- Google Play Console account required ($25 one-time)
- Internal testing track
- Play Store submission

### 12. Timeline Estimate

- **Phase 1:** 1-2 weeks
- **Phase 2:** 2-3 weeks
- **Phase 3:** 1 week
- **Phase 4:** 1-2 weeks
- **Phase 5:** 1 week
- **Total:** 6-9 weeks

### 13. Resources

- [React Native Documentation](https://reactnative.dev/)
- [React Navigation](https://reactnavigation.org/)
- [Expo Documentation](https://docs.expo.dev/)
- [React Native Community](https://github.com/react-native-community)

## Notes

- Keep web version maintained during migration
- Consider using Expo for faster development
- Plan for API compatibility (same backend for web and mobile)
- Consider code sharing between web and mobile where possible
- PWA alternative? (Progressive Web App might be simpler than full native)

## Decision Required

Before starting migration, decide:
1. Expo vs React Native CLI
2. Support both web and mobile, or mobile-only?
3. iOS first, Android first, or both simultaneously?
4. Native modules needed? (camera, biometrics, etc.)

## Current Blocker

Migration to React Native was requested but web implementation was completed first.
This document tracks the migration plan for when ready to proceed.