# Next Best Move

Test v3.4.2 by approving the reviewed PooleShield package archive entries, merging them into the existing trusted baseline with `--merge-existing`, then rerunning `file-av-scan-baseline` with the default rule pack. Expected outcome: `0 REQUIRE_APPROVAL`, `0 BLOCK`, archive/package entries become `ALLOW_LOG` by baseline.
