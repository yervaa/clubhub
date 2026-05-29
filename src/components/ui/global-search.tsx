"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ClubColorDot } from "@/components/ui/club-color-dot";

export const GLOBAL_SEARCH_OPEN_EVENT = "clubora:global-search-open";

type SearchClub = { id: string; name: string; description: string | null };
type SearchAnnouncement = { id: string; title: string; club_id: string; club_name: string };
type SearchEvent = {
  id: string;
  title: string;
  club_id: string;
  club_name: string;
  event_date: string;
};
type SearchMember = {
  id: string;
  full_name: string | null;
  email: string | null;
  shared_club_id: string;
};

type SearchResults = {
  clubs: SearchClub[];
  announcements: SearchAnnouncement[];
  events: SearchEvent[];
  members: SearchMember[];
};

const EMPTY_RESULTS: SearchResults = {
  clubs: [],
  announcements: [],
  events: [],
  members: [],
};

type FlatResult = {
  key: string;
  href: string;
  primary: string;
  secondary: string;
  clubName?: string;
  category: "club" | "announcement" | "event" | "member";
};

function buildFlatResults(results: SearchResults): FlatResult[] {
  const flat: FlatResult[] = [];

  for (const club of results.clubs) {
    flat.push({
      key: `club-${club.id}`,
      href: `/clubs/${club.id}`,
      primary: club.name,
      secondary: club.description?.trim() || "Club",
      clubName: club.name,
      category: "club",
    });
  }

  for (const item of results.announcements) {
    flat.push({
      key: `announcement-${item.id}`,
      href: `/clubs/${item.club_id}/announcements`,
      primary: item.title,
      secondary: item.club_name,
      clubName: item.club_name,
      category: "announcement",
    });
  }

  for (const item of results.events) {
    const when = new Date(item.event_date).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
    flat.push({
      key: `event-${item.id}`,
      href: `/clubs/${item.club_id}/events`,
      primary: item.title,
      secondary: `${item.club_name} · ${when}`,
      clubName: item.club_name,
      category: "event",
    });
  }

  for (const item of results.members) {
    const primary = item.full_name?.trim() || item.email?.split("@")[0] || "Member";
    flat.push({
      key: `member-${item.id}`,
      href: `/clubs/${item.shared_club_id}/members`,
      primary,
      secondary: item.email?.trim() || "Member",
      category: "member",
    });
  }

  return flat;
}

function CategoryIcon({ category, clubName }: { category: FlatResult["category"]; clubName?: string }) {
  if (category === "club" && clubName) {
    return <ClubColorDot clubName={clubName} size="sm" />;
  }

  const iconClass = "global-search__category-icon";
  if (category === "announcement") {
    return (
      <span className={iconClass} aria-hidden>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path strokeWidth="2" strokeLinecap="round" d="M11 5L6 9H3v6h3l5 4V5zM16 9a4 4 0 010 6M19 7a7 7 0 010 10" />
        </svg>
      </span>
    );
  }

  if (category === "event") {
    return (
      <span className={iconClass} aria-hidden>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M8 7V3m8 4V3M4 11h16M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
          />
        </svg>
      </span>
    );
  }

  return (
    <span className={iconClass} aria-hidden>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M16 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z"
        />
      </svg>
    </span>
  );
}

function openGlobalSearch() {
  window.dispatchEvent(new CustomEvent(GLOBAL_SEARCH_OPEN_EVENT));
}

type GlobalSearchTriggerProps = {
  className?: string;
};

export function GlobalSearchTrigger({ className = "" }: GlobalSearchTriggerProps) {
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad|iPod/.test(navigator.platform);

  return (
    <button
      type="button"
      onClick={openGlobalSearch}
      className={`global-search-trigger ${className}`.trim()}
      aria-label="Search clubs, announcements, events, and members"
    >
      <span className="global-search-trigger__icon" aria-hidden>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M10.5 18a7.5 7.5 0 100-15 7.5 7.5 0 000 15zM16.5 16.5L21 21"
          />
        </svg>
      </span>
      <span className="global-search-trigger__placeholder">Search...</span>
      <kbd className="global-search-trigger__kbd">{isMac ? "⌘K" : "Ctrl+K"}</kbd>
    </button>
  );
}

export function GlobalSearch() {
  const router = useRouter();
  const dialogTitleId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResults>(EMPTY_RESULTS);
  const [loading, setLoading] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const flatResults = useMemo(() => buildFlatResults(results), [results]);
  const resultSections = useMemo(() => {
    const labels: Record<FlatResult["category"], string> = {
      club: "Clubs",
      announcement: "Announcements",
      event: "Events",
      member: "Members",
    };
    const order: FlatResult["category"][] = ["club", "announcement", "event", "member"];
    let index = -1;

    return order
      .map((category) => ({
        label: labels[category],
        rows: flatResults
          .filter((item) => item.category === category)
          .map((item) => ({ item, index: ++index })),
      }))
      .filter((section) => section.rows.length > 0);
  }, [flatResults]);
  const trimmedQuery = query.trim();
  const showResults = trimmedQuery.length >= 2;
  const hasAnyResults =
    results.clubs.length > 0 ||
    results.announcements.length > 0 ||
    results.events.length > 0 ||
    results.members.length > 0;

  const close = useCallback(() => {
    setIsOpen(false);
    setActiveIndex(-1);
  }, []);

  const navigateTo = useCallback(
    (href: string) => {
      close();
      setQuery("");
      setResults(EMPTY_RESULTS);
      router.push(href);
    },
    [close, router],
  );

  useEffect(() => {
    const onOpen = () => {
      setIsOpen(true);
      setActiveIndex(-1);
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpen();
      }
    };

    window.addEventListener(GLOBAL_SEARCH_OPEN_EVENT, onOpen);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener(GLOBAL_SEARCH_OPEN_EVENT, onOpen);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }

      if (!showResults || flatResults.length === 0) return;

      if (event.key === "ArrowDown") {
        event.preventDefault();
        setActiveIndex((index) => (index < flatResults.length - 1 ? index + 1 : 0));
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setActiveIndex((index) => (index > 0 ? index - 1 : flatResults.length - 1));
      } else if (event.key === "Enter" && activeIndex >= 0) {
        event.preventDefault();
        const target = flatResults[activeIndex];
        if (target) navigateTo(target.href);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isOpen, showResults, flatResults, activeIndex, close, navigateTo]);

  useEffect(() => {
    if (!isOpen) return;

    if (trimmedQuery.length < 2) {
      setResults(EMPTY_RESULTS);
      setLoading(false);
      setActiveIndex(-1);
      return;
    }

    const controller = new AbortController();
    setLoading(true);

    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(trimmedQuery)}`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          setResults(EMPTY_RESULTS);
          return;
        }

        const data = (await response.json()) as SearchResults;
        setResults(data);
        setActiveIndex(-1);
      } catch (error) {
        if ((error as Error).name !== "AbortError") {
          setResults(EMPTY_RESULTS);
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }, 300);

    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [trimmedQuery, isOpen]);

  if (!isOpen) return null;

  return (
    <div className="global-search-overlay" role="presentation" onClick={close}>
      <div
        className="global-search-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={dialogTitleId}
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id={dialogTitleId} className="sr-only">
          Search
        </h2>

        <div className={`global-search__input-wrap${showResults ? " has-results" : ""}`}>
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search clubs, announcements, events, members…"
            className="global-search__input"
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            aria-autocomplete="list"
            aria-controls="global-search-results"
          />
          {loading ? <p className="global-search__loading">Searching…</p> : null}
        </div>

        {showResults ? (
          <div id="global-search-results" className="global-search__results" role="listbox">
            {!loading && !hasAnyResults ? (
              <p className="global-search__empty">No results for &lsquo;{trimmedQuery}&rsquo;</p>
            ) : null}

            {resultSections.map((section) => (
              <section key={section.label}>
                <p className="global-search__category">{section.label}</p>
                {section.rows.map(({ item, index }) => {
                  const isActive = index === activeIndex;

                  return (
                    <button
                      key={item.key}
                      type="button"
                      role="option"
                      aria-selected={isActive}
                      className={`global-search__row${isActive ? " is-active" : ""}`}
                      onMouseEnter={() => setActiveIndex(index)}
                      onClick={() => navigateTo(item.href)}
                    >
                      <CategoryIcon category={item.category} clubName={item.clubName} />
                      <span className="global-search__row-text">
                        <span className="global-search__row-primary">{item.primary}</span>
                        <span className="global-search__row-secondary">{item.secondary}</span>
                      </span>
                    </button>
                  );
                })}
              </section>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
