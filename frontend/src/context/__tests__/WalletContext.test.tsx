import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { WalletProvider } from '../WalletContext';
import { useWallet } from '../WalletContextValue';
import { isConnected } from '@stellar/freighter-api';

vi.mock('@stellar/freighter-api', () => ({
  isConnected: vi.fn().mockResolvedValue({ isConnected: true }),
  isAllowed: vi.fn().mockResolvedValue({ isAllowed: true }),
  getAddress: vi.fn().mockResolvedValue({ address: 'GTEST123' }),
  setAllowed: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../wallets/registry', () => ({
  detectAvailableWallets: vi.fn().mockResolvedValue(['freighter']),
}));

const TestComponent = () => {
  const { address, isConnected, error, disconnect } = useWallet();
  return (
    <div>
      <div data-testid="address">{address || 'Not connected'}</div>
      <div data-testid="is-connected">{isConnected ? 'Connected' : 'Disconnected'}</div>
      <div data-testid="error">{error || 'No error'}</div>
      <button onClick={disconnect}>Disconnect</button>
    </div>
  );
};

describe('WalletContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isConnected).mockResolvedValue({ isConnected: true });
    localStorage.clear();
  });

  it('should detect wallet and show address', async () => {
    render(
      <WalletProvider>
        <TestComponent />
      </WalletProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('address')).toHaveTextContent('GTEST123');
    }, { timeout: 3000 });
  });

  it('should disconnect and clear error state', async () => {
    render(
      <WalletProvider>
        <TestComponent />
      </WalletProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('address')).toHaveTextContent('GTEST123');
    });

    const disconnectBtn = screen.getByText('Disconnect');
    fireEvent.click(disconnectBtn);

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('Disconnected');
      expect(screen.getByTestId('error')).toHaveTextContent('No error');
    });
  });

  it('should surface connection errors', async () => {
    vi.mocked(isConnected).mockRejectedValue(new Error('Connection failed'));

    render(
      <WalletProvider>
        <TestComponent />
      </WalletProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('error')).toHaveTextContent('Connection failed');
    });
  });
});
