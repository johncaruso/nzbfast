//! The read seam's stale-statement handling, moved out of daemon_tests.rs
//! under the size gate (TODO 106). `use super::*` carries `with_daemon`
//! and everything daemon.rs's test module already has in scope.

use super::*;

/// A pooled read whose statements go STALE must reach the caller as an
/// error, not as an empty answer.
///
/// `index_read_checked` takes an `FnOnce(&Index) -> Option<T>`, so every
/// caller's `.ok()` has already discarded the `rusqlite::Error` by the
/// time the seam sees a result: a query that failed and a query that
/// legitimately matched nothing are the same `None`. That is what turned
/// `SqliteFailure(SchemaChanged/17, "vtable constructor failed: rel_fts")`
/// into `<newznab:response total="0"/>` and delivered it to Sonarr as
/// "this indexer has nothing" (see the memory note on 16 Aug's newznab
/// flake, and `nzbkit`'s `index::retry`).
///
/// Retrying on `None` cannot be the fix - it would be wrong AND would
/// double the work of every miss - so nzbkit stamps the fault on the
/// CONNECTION, where it survives the flattening, and this seam reads the
/// stamp either side of the closure.
#[cfg(feature = "indexer")]
#[test]
fn a_stale_statement_on_a_pooled_read_is_not_an_empty_answer() {
    with_daemon("schemafault", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // A read-write open runs the migrations and publishing it sets
        // `index_migrated`, which is what routes queries to the read POOL
        // instead of the startup fallback to the write mutex.
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open the index");
        d.publish_index(era, fresh);
        let q = nzbkit::index::BrowseQuery {
            limit: 10,
            ..Default::default()
        };

        // Control: a free pool answers, and an index with no rows in it
        // is a perfectly good `Ok(Some(empty))`. Nothing below is allowed
        // to turn that into an error.
        assert!(
            matches!(d.index_read_checked(|ix| ix.browse(&q).ok()), Ok(Some(_))),
            "a free pool answers an empty index with an empty result"
        );

        // One stale statement: nzbkit prepares again and the caller never
        // learns it happened.
        assert!(
            matches!(
                d.index_read_checked(|ix| {
                    ix.debug_fail_next_queries(1);
                    ix.browse(&q).ok()
                }),
                Ok(Some(_))
            ),
            "a single SQLITE_SCHEMA is retried away, not surfaced"
        );

        // A fault that outlives the retry. The closure's `.ok()` throws
        // the error away exactly as every real caller does, so before the
        // stamp this was `Ok(None)` - drawn as "nothing found".
        assert_eq!(
            d.index_read_checked(|ix| {
                ix.debug_fail_next_queries(2);
                ix.browse(&q).ok()
            })
            .err(),
            Some(super::super::daemon_index::IndexBusy::SchemaChanged),
            "a read that FAILED must not be reported as a read that found nothing"
        );
    });
}
