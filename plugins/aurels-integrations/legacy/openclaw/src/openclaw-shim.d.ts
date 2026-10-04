declare module "openclaw/plugin-sdk/plugin-entry" {
  export function definePluginEntry<T>(entry: T): T;
}

declare module "openclaw/plugin-sdk" {
  export function definePluginEntry<T>(entry: T): T;
}
