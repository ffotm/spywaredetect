export { };

declare global {
    interface Window {
        electron?: {
            getBackendUrl: () => Promise<string>;
        };
    }
}