#!/usr/bin/env python3
from pathlib import Path

path = Path("libraries/slope/src/memory/mod.rs")
text = path.read_text(encoding="utf-8")
old = '''    fn allocate_page(&self) -> Option<*mut u8> {
        let page = self
            .next_page
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < USER_HEAP_PAGES).then_some(current + 1)
            })
            .ok()?;
        // SAFETY: `page` was uniquely reserved by the atomic cursor. The
        // arena never hands this page out again and all callers initialize it
        // through the serialized slab state before publishing allocations.
        Some(unsafe { (*self.backing.get()).0.as_mut_ptr().add(page * PAGE_SIZE) })
    }'''
new = '''    fn allocate_page(&self) -> Option<*mut u8> {
        let mut current = self.next_page.load(Ordering::Acquire);
        let page = loop {
            if current >= USER_HEAP_PAGES {
                return None;
            }
            match self.next_page.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(reserved) => break reserved,
                Err(observed) => current = observed,
            }
        };
        // SAFETY: `page` was uniquely reserved by the atomic cursor. The
        // arena never hands this page out again and all callers initialize it
        // through the serialized slab state before publishing allocations.
        Some(unsafe { (*self.backing.get()).0.as_mut_ptr().add(page * PAGE_SIZE) })
    }'''
if text.count(old) != 1:
    raise SystemExit("unexpected generated page-allocation implementation")
path.write_text(text.replace(old, new), encoding="utf-8")
