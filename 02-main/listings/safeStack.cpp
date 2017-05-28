/// Check whether a given allocation must be put on the safe
/// stack or not. The function analyzes all uses of AI and checks whether it is
/// only accessed in a memory safe way (as decided statically).
bool SafeStack::IsSafeStackAlloca(const Value *AllocaPtr, uint64_t AllocaSize) {
  // Go through all uses of this alloca and check whether all accesses to the
  // allocated object are statically known to be memory safe and, hence, the
  // object can be placed on the safe stack.
  SmallPtrSet<const Value *, 16> Visited;
  SmallVector<const Value *, 8> WorkList;
  WorkList.push_back(AllocaPtr);

  // A DFS search through all uses of the alloca in bitcasts/PHI/GEPs/etc.
  while (!WorkList.empty()) {
    const Value *V = WorkList.pop_back_val();
    for (const Use &UI : V->uses()) {
      auto I = cast<const Instruction>(UI.getUser());
      assert(V == UI.get());

      switch (I->getOpcode()) {
      case Instruction::Load: {
        if (!IsAccessSafe(UI, DL->getTypeStoreSize(I->getType()), AllocaPtr,
                          AllocaSize))
          return false;
        break;
      }
      case Instruction::VAArg:
        // "va-arg" from a pointer is safe.
        break;
      case Instruction::Store: {
        if (V == I->getOperand(0)) {
          // Stored the pointer - conservatively assume it may be unsafe.
          DEBUG(dbgs() << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                       << "\n            store of address: " << *I << "\n");
          return false;
        }

        if (!IsAccessSafe(UI, DL->getTypeStoreSize(I->getOperand(0)->getType()),
                          AllocaPtr, AllocaSize))
          return false;
        break;
      }
      case Instruction::Ret: {
        // Information leak.
        return false;
      }

      case Instruction::Call:
      case Instruction::Invoke: {
        ImmutableCallSite CS(I);

        if (const IntrinsicInst *II = dyn_cast<IntrinsicInst>(I)) {
          if (II->getIntrinsicID() == Intrinsic::lifetime_start ||
              II->getIntrinsicID() == Intrinsic::lifetime_end)
            continue;
        }

        if (const MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I)) {
          if (!IsMemIntrinsicSafe(MI, UI, AllocaPtr, AllocaSize)) {
            DEBUG(dbgs() << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                         << "\n            unsafe memintrinsic: " << *I
                         << "\n");
            return false;
          }
          continue;
        }

        // LLVM 'nocapture' attribute is only set for arguments whose address
        // is not stored, passed around, or used in any other non-trivial way.
        // We assume that passing a pointer to an object as a 'nocapture
        // readnone' argument is safe.
        // FIXME: a more precise solution would require an interprocedural
        // analysis here, which would look at all uses of an argument inside
        // the function being called.
        ImmutableCallSite::arg_iterator B = CS.arg_begin(), E = CS.arg_end();
        for (ImmutableCallSite::arg_iterator A = B; A != E; ++A)
          if (A->get() == V)
            if (!(CS.doesNotCapture(A - B) && (CS.doesNotAccessMemory(A - B) ||
                                               CS.doesNotAccessMemory()))) {
              DEBUG(dbgs() << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                           << "\n            unsafe call: " << *I << "\n");
              return false;
            }
        continue;
      }

      default:
        if (Visited.insert(I).second)
          WorkList.push_back(cast<const Instruction>(I));
      }
    }
  }

  // All uses of the alloca are safe, we can place it on the safe stack.
  return true;
}
