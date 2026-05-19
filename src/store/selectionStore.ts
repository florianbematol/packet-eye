// Tiny store for the currently selected connection id (used by the
// globe + the info panel that floats over it).

import { create } from "zustand";

interface SelectionState {
  selectedId: string | null;
  hoveredId: string | null;
  select: (id: string | null) => void;
  hover: (id: string | null) => void;
}

export const useSelectionStore = create<SelectionState>((set) => ({
  selectedId: null,
  hoveredId: null,
  select: (id) => set({ selectedId: id }),
  hover: (id) => set({ hoveredId: id }),
}));
