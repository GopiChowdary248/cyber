import React, { useState, useEffect, useRef } from 'react';
import { 
  MagnifyingGlassIcon, 
  ChevronUpIcon, 
  ChevronDownIcon,
  DocumentIcon,
  FolderIcon,
  CodeBracketIcon
} from '@heroicons/react/24/outline';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';

interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder';
  path: string;
  children?: FileNode[];
  language?: string;
  size?: number;
  lastModified?: string;
}

interface EnhancedCodeBrowserProps {
  files: FileNode[];
  onFileSelect: (file: FileNode) => void;
  selectedFile?: FileNode;
  className?: string;
}

const EnhancedCodeBrowser: React.FC<EnhancedCodeBrowserProps> = ({
  files,
  onFileSelect,
  selectedFile,
  className = ''
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [filteredFiles, setFilteredFiles] = useState<FileNode[]>(files);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const fileListRef = useRef<HTMLDivElement>(null);

  // Keyboard shortcuts for navigation
  const shortcuts = useKeyboardShortcuts([
    {
      key: 'ArrowDown',
      description: 'Next file',
      action: () => navigateFiles(1)
    },
    {
      key: 'ArrowUp',
      description: 'Previous file',
      action: () => navigateFiles(-1)
    },
    {
      key: 'Enter',
      description: 'Open selected file',
      action: () => {
        if (filteredFiles[selectedIndex]) {
          onFileSelect(filteredFiles[selectedIndex]);
        }
      }
    },
    {
      key: 'f',
      ctrl: true,
      description: 'Focus search',
      action: () => {
        const searchInput = document.getElementById('file-search-input');
        searchInput?.focus();
      }
    }
  ]);

  useEffect(() => {
    filterFiles();
  }, [searchQuery, files]);

  useEffect(() => {
    // Reset selection when files change
    setSelectedIndex(0);
  }, [filteredFiles]);

  const filterFiles = () => {
    if (!searchQuery.trim()) {
      setFilteredFiles(files);
      return;
    }

    const query = searchQuery.toLowerCase();
    const filtered: FileNode[] = [];

    const searchInNode = (node: FileNode): boolean => {
      if (node.name.toLowerCase().includes(query)) {
        filtered.push(node);
        return true;
      }

      if (node.children) {
        const hasMatch = node.children.some(searchInNode);
        if (hasMatch) {
          // Expand folder if it contains matching files
          setExpandedFolders(prev => new Set(prev).add(node.id));
        }
        return hasMatch;
      }

      return false;
    };

    files.forEach(searchInNode);
    setFilteredFiles(filtered);
  };

  const navigateFiles = (direction: number) => {
    if (filteredFiles.length === 0) return;
    
    const newIndex = (selectedIndex + direction + filteredFiles.length) % filteredFiles.length;
    setSelectedIndex(newIndex);
    
    // Scroll to selected item
    setTimeout(() => {
      const selectedElement = fileListRef.current?.querySelector(`[data-index="${newIndex}"]`);
      selectedElement?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 0);
  };

  const toggleFolder = (folderId: string) => {
    setExpandedFolders(prev => {
      const newSet = new Set(prev);
      if (newSet.has(folderId)) {
        newSet.delete(folderId);
      } else {
        newSet.add(folderId);
      }
      return newSet;
    });
  };

  const renderFileNode = (node: FileNode, level: number = 0, index: number) => {
    const isExpanded = expandedFolders.has(node.id);
    const isSelected = selectedFile?.id === node.id;
    const isHighlighted = filteredFiles[index]?.id === node.id;

    return (
      <div key={node.id}>
        <div
          className={`flex items-center space-x-2 px-2 py-1 cursor-pointer hover:bg-gray-100 transition-colors ${
            isSelected ? 'bg-blue-100 border-r-2 border-blue-500' : ''
          } ${isHighlighted ? 'bg-yellow-50' : ''}`}
          style={{ paddingLeft: `${level * 16 + 8}px` }}
          onClick={() => {
            if (node.type === 'folder') {
              toggleFolder(node.id);
            } else {
              onFileSelect(node);
            }
          }}
          data-index={index}
        >
          {node.type === 'folder' ? (
            <>
              <FolderIcon className="w-4 h-4 text-blue-500" />
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  toggleFolder(node.id);
                }}
                className="p-1 hover:bg-gray-200 rounded"
              >
                {isExpanded ? (
                  <ChevronDownIcon className="w-3 h-3" />
                ) : (
                  <ChevronUpIcon className="w-3 h-3" />
                )}
              </button>
            </>
          ) : (
            <DocumentIcon className="w-4 h-4 text-gray-500" />
          )}
          
          <span className="truncate flex-1">{node.name}</span>
          
          {node.language && (
            <span className="text-xs text-gray-400 px-1 py-0.5 bg-gray-100 rounded">
              {node.language}
            </span>
          )}
        </div>

        {node.type === 'folder' && isExpanded && node.children && (
          <div>
            {node.children.map((child, childIndex) => 
              renderFileNode(child, level + 1, index + childIndex + 1)
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`bg-white border border-gray-200 rounded-lg ${className}`}>
      {/* Search Header */}
      <div className="p-3 border-b border-gray-200">
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            id="file-search-input"
            type="text"
            placeholder="Search files..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        {/* Search shortcuts hint */}
        <div className="mt-2 text-xs text-gray-500">
          <span className="font-medium">Shortcuts:</span> Ctrl+F to focus search, ↑↓ to navigate, Enter to open
        </div>
      </div>

      {/* File Tree */}
      <div 
        ref={fileListRef}
        className="max-h-96 overflow-y-auto"
      >
        {filteredFiles.length === 0 ? (
          <div className="p-4 text-center text-gray-500">
            {searchQuery ? 'No files match your search' : 'No files available'}
          </div>
        ) : (
          <div>
            {filteredFiles.map((file, index) => renderFileNode(file, 0, index))}
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div className="px-3 py-2 border-t border-gray-200 bg-gray-50 text-xs text-gray-600">
        {filteredFiles.length} file{filteredFiles.length !== 1 ? 's' : ''}
        {searchQuery && ` matching "${searchQuery}"`}
      </div>
    </div>
  );
};

export default EnhancedCodeBrowser;
