window.BENCHMARK_DATA = {
  "lastUpdate": 1795879038959,
  "repoUrl": "https://github.com/vtxos/runtime",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b8254f69cde2f96646ae20d364e195d20672ac0f",
          "message": "Merge pull request #1 from BitspendPayment/merkle-block-store\n\nNew Runtime (Yippy Hurra)",
          "timestamp": "2026-09-26T09:21:32+03:00",
          "tree_id": "20dfc264bbc2618301549bcaaf213c6050c44a02",
          "url": "https://github.com/BitspendPayment/enclave-runtime/commit/b8254f69cde2f96646ae20d364e195d20672ac0f"
        },
        "date": 1790404528763,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 25825,
            "range": "± 3807",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 139946,
            "range": "± 9382",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 769513,
            "range": "± 25547",
            "unit": "ns/iter"
          },
          {
            "name": "guest/mount",
            "value": 52638,
            "range": "± 1541",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/1024",
            "value": 414193,
            "range": "± 19436",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/65536",
            "value": 487052,
            "range": "± 24167",
            "unit": "ns/iter"
          },
          {
            "name": "write_and_commit/1048576",
            "value": 1578441,
            "range": "± 177612",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/1",
            "value": 83476,
            "range": "± 3381",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/16",
            "value": 151169,
            "range": "± 5929",
            "unit": "ns/iter"
          },
          {
            "name": "commit_by_dirty_blocks/256",
            "value": 1301640,
            "range": "± 47827",
            "unit": "ns/iter"
          },
          {
            "name": "random_read/4096",
            "value": 2868,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "random_read/65536",
            "value": 5190,
            "range": "± 155",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/10",
            "value": 1857,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/1000",
            "value": 7011,
            "range": "± 247",
            "unit": "ns/iter"
          },
          {
            "name": "directory_lookup/10000",
            "value": 13009,
            "range": "± 313",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c2ea60ea573ba294cd9a807a9bf3b174d78e7378",
          "message": "Merge pull request #3 from BitspendPayment/nitro-deployment\n\nZFS storage: per-tenant pools and the rollback-integrity fix",
          "timestamp": "2026-10-10T17:59:16+03:00",
          "tree_id": "275e6ad5dbc3e849ec250ed7ef3b85f2f6135002",
          "url": "https://github.com/BitspendPayment/enclave-runtime/commit/c2ea60ea573ba294cd9a807a9bf3b174d78e7378"
        },
        "date": 1791644863781,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 34886,
            "range": "± 2408",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 125501,
            "range": "± 7063",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 834533,
            "range": "± 1164455",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c4a0b9650561b7113664cf5cf94331168d4d1deb",
          "message": "Merge pull request #4 from vtxos/telemetry\n\nGuest telemetry: tracing to X-Ray, metrics to CloudWatch",
          "timestamp": "2026-10-11T19:46:54+03:00",
          "tree_id": "40dd4b076d3329b6d595171623fdaf3f91a720bc",
          "url": "https://github.com/vtxos/enclave-runtime/commit/c4a0b9650561b7113664cf5cf94331168d4d1deb"
        },
        "date": 1791737558617,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 32922,
            "range": "± 2902",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 203704,
            "range": "± 9285",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1132850,
            "range": "± 701095",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0022862507cec2bb0821ffece0b6f39506112897",
          "message": "Merge pull request #7 from vtxos/reproducible-zfs-modules\n\nBuild the same enclave image on every machine",
          "timestamp": "2026-10-15T11:31:03+03:00",
          "tree_id": "0608bbd9b0355f5f321b3d542b71aa6d9764f6f8",
          "url": "https://github.com/vtxos/runtime/commit/0022862507cec2bb0821ffece0b6f39506112897"
        },
        "date": 1792053849323,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 49628,
            "range": "± 6323",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 269712,
            "range": "± 8249",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1182294,
            "range": "± 50013",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bf5f8044691dca05b77faf6754be626254a49261",
          "message": "Merge pull request #6 from vtxos/drop-publish-dev-enclave\n\nStop publishing dev enclave bundles",
          "timestamp": "2026-10-15T12:46:04+03:00",
          "tree_id": "040e877d0d8f09e79cb7bb095aa6af686c1c4ead",
          "url": "https://github.com/vtxos/runtime/commit/bf5f8044691dca05b77faf6754be626254a49261"
        },
        "date": 1792057961603,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 53863,
            "range": "± 6634",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 273371,
            "range": "± 11657",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1205329,
            "range": "± 305822",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ff14f39428d2582e97b2b40352aa8b503300006c",
          "message": "Merge pull request #8 from vtxos/readme-aegira\n\ndocs: the project is Aegira",
          "timestamp": "2026-10-18T01:59:51+03:00",
          "tree_id": "ac72e5c4269a6c345bd86bee08399e3143ddc7b0",
          "url": "https://github.com/vtxos/runtime/commit/ff14f39428d2582e97b2b40352aa8b503300006c"
        },
        "date": 1792278382939,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 50824,
            "range": "± 5649",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 273585,
            "range": "± 10906",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1234064,
            "range": "± 82149",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "63869b2c875d845805ca959f4016afd360425a1c",
          "message": "Merge pull request #9 from vtxos/client-keyed-tenants\n\nOwner-keyed tenants, enclave:signer, tasks through AWS, and a client for native apps",
          "timestamp": "2026-11-21T23:19:39+02:00",
          "tree_id": "bd1b360e3213d6846ec9e5e779af0c9c86fcd383",
          "url": "https://github.com/vtxos/runtime/commit/63869b2c875d845805ca959f4016afd360425a1c"
        },
        "date": 1795296704164,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 32818,
            "range": "± 2300",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 128786,
            "range": "± 6767",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 963821,
            "range": "± 1260268",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b747e84415dca8eb89a7ad15e7872d558ce6f276",
          "message": "Merge pull request #10 from vtxos/release-trial/ios\n\nThe React Native library's release builds on both platforms, and can be tried without publishing",
          "timestamp": "2026-11-21T23:55:39+02:00",
          "tree_id": "1520551326e52f6d04678ac2320ed63e5c97916e",
          "url": "https://github.com/vtxos/runtime/commit/b747e84415dca8eb89a7ad15e7872d558ce6f276"
        },
        "date": 1795298662408,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 50903,
            "range": "± 8935",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 240066,
            "range": "± 6456",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1097640,
            "range": "± 65084",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ab001ab62bbe2f9e0c86481721f4189964bbe8e5",
          "message": "Merge pull request #11 from vtxos/release-trial/pack\n\nThe React Native package includes the iOS framework, and a release trial checks the package",
          "timestamp": "2026-11-22T00:22:05+02:00",
          "tree_id": "264a406a381c17945654ff003c60968492822c59",
          "url": "https://github.com/vtxos/runtime/commit/ab001ab62bbe2f9e0c86481721f4189964bbe8e5"
        },
        "date": 1795300093261,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 17927,
            "range": "± 1045",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 126881,
            "range": "± 5282",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 621114,
            "range": "± 19093",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3f0df455feb18ad58990eb57da1914fa2e1062fc",
          "message": "Merge pull request #12 from vtxos/fix/vsock-own-cid\n\nfix(qemu): the enclave reaches gvproxy through a listener that binds every CID",
          "timestamp": "2026-11-22T10:53:37+02:00",
          "tree_id": "0112fccb529b264c28a4e06480daa26bea3f55d0",
          "url": "https://github.com/vtxos/runtime/commit/3f0df455feb18ad58990eb57da1914fa2e1062fc"
        },
        "date": 1795337980566,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 24501,
            "range": "± 1837",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 169349,
            "range": "± 14733",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1539914,
            "range": "± 1319742",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "94e16e42679ee43a54e3999350865774de1c2302",
          "message": "Merge pull request #13 from vtxos/fix/review-findings\n\nReview fixes, and registering again is recovering",
          "timestamp": "2026-11-24T15:57:49+02:00",
          "tree_id": "cc21d1a0460f09672b49d656786ce3214800c110",
          "url": "https://github.com/vtxos/runtime/commit/94e16e42679ee43a54e3999350865774de1c2302"
        },
        "date": 1795529021352,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 24388,
            "range": "± 2215",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 158440,
            "range": "± 16248",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1425166,
            "range": "± 1055874",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a3f778118f42a9f5f64168c4803b68f344d594d8",
          "message": "Merge pull request #14 from vtxos/retention-default-one-week\n\nstore: anchors and registry records are locked for a week by default",
          "timestamp": "2026-11-28T09:33:53+02:00",
          "tree_id": "25fe984f0d7f37a361671c10ac125b9219040aa1",
          "url": "https://github.com/vtxos/runtime/commit/a3f778118f42a9f5f64168c4803b68f344d594d8"
        },
        "date": 1795851691791,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 29190,
            "range": "± 2638",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 198237,
            "range": "± 15520",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 1482030,
            "range": "± 920333",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshuaaruokhaitech@gmail.com",
            "name": "Aruokhai Joshua",
            "username": "aruokhai"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0ff4504b373e1302e83cde1d479ec810c14eff09",
          "message": "Merge pull request #15 from vtxos/feat/enclave-creates-its-key\n\nEach release's enclave creates its own KMS key at genesis",
          "timestamp": "2026-11-28T17:10:56+02:00",
          "tree_id": "21a0412975a15027738e63c920474c66ba8f24e2",
          "url": "https://github.com/vtxos/runtime/commit/0ff4504b373e1302e83cde1d479ec810c14eff09"
        },
        "date": 1795879038285,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest/instantiate",
            "value": 18848,
            "range": "± 1282",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/trivial",
            "value": 143875,
            "range": "± 4961",
            "unit": "ns/iter"
          },
          {
            "name": "guest/dispatch/committing",
            "value": 653895,
            "range": "± 55211",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}