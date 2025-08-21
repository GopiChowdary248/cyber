import { useEffect, useCallback } from 'react';

export interface KeyboardShortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  meta?: boolean;
  description: string;
  action: () => void;
}

export interface ShortcutGroup {
  name: string;
  shortcuts: KeyboardShortcut[];
}

export const useKeyboardShortcuts = (shortcuts: KeyboardShortcut[]) => {
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    // Ignore shortcuts when typing in input fields
    if (
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLTextAreaElement ||
      event.target instanceof HTMLSelectElement
    ) {
      return;
    }

    for (const shortcut of shortcuts) {
      if (
        event.key.toLowerCase() === shortcut.key.toLowerCase() &&
        !!event.ctrlKey === !!shortcut.ctrl &&
        !!event.shiftKey === !!shortcut.shift &&
        !!event.altKey === !!shortcut.alt &&
        !!event.metaKey === !!shortcut.meta
      ) {
        event.preventDefault();
        shortcut.action();
        break;
      }
    }
  }, [shortcuts]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);

  return shortcuts;
};

// Predefined shortcut groups for SAST module
export const SAST_SHORTCUTS: ShortcutGroup[] = [
  {
    name: 'Navigation',
    shortcuts: [
      {
        key: 'g',
        ctrl: true,
        description: 'Go to project',
        action: () => console.log('Ctrl+G: Go to project')
      },
      {
        key: 's',
        ctrl: true,
        description: 'Search issues',
        action: () => console.log('Ctrl+S: Search issues')
      },
      {
        key: 'f',
        ctrl: true,
        description: 'Find in code',
        action: () => console.log('Ctrl+F: Find in code')
      },
      {
        key: 'b',
        ctrl: true,
        description: 'Go back',
        action: () => window.history.back()
      },
      {
        key: 'n',
        ctrl: true,
        description: 'Next issue',
        action: () => console.log('Ctrl+N: Next issue')
      },
      {
        key: 'p',
        ctrl: true,
        description: 'Previous issue',
        action: () => console.log('Ctrl+P: Previous issue')
      }
    ]
  },
  {
    name: 'Actions',
    shortcuts: [
      {
        key: 'Enter',
        description: 'Open selected item',
        action: () => console.log('Enter: Open selected item')
      },
      {
        key: 'Delete',
        description: 'Delete selected item',
        action: () => console.log('Delete: Delete selected item')
      },
      {
        key: 'r',
        ctrl: true,
        description: 'Refresh data',
        action: () => console.log('Ctrl+R: Refresh data')
      },
      {
        key: 'e',
        ctrl: true,
        description: 'Edit selected item',
        action: () => console.log('Ctrl+E: Edit selected item')
      },
      {
        key: 'a',
        ctrl: true,
        description: 'Select all',
        action: () => console.log('Ctrl+A: Select all')
      }
    ]
  },
  {
    name: 'Views',
    shortcuts: [
      {
        key: '1',
        ctrl: true,
        description: 'Issues view',
        action: () => console.log('Ctrl+1: Issues view')
      },
      {
        key: '2',
        ctrl: true,
        description: 'Security hotspots view',
        action: () => console.log('Ctrl+2: Security hotspots view')
      },
      {
        key: '3',
        ctrl: true,
        description: 'Code coverage view',
        action: () => console.log('Ctrl+3: Code coverage view')
      },
      {
        key: '4',
        ctrl: true,
        description: 'Quality gates view',
        action: () => console.log('Ctrl+4: Quality gates view')
      },
      {
        key: 'h',
        ctrl: true,
        description: 'Toggle coverage overlay',
        action: () => console.log('Ctrl+H: Toggle coverage overlay')
      }
    ]
  }
];

export default useKeyboardShortcuts;
