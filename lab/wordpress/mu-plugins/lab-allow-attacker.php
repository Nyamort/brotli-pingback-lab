<?php
/**
 * Plugin Name: Lab - allow the Docker-internal attacker host
 * Description: Lab-only filter. It allows exactly one hostname, "attacker",
 *              which only resolves on the Docker network.
 *
 * WordPress pingback uses wp_safe_remote_get(), which rejects private IPs.
 * The lab payload server is a Docker service with a private address, so the
 * stock check would refuse it. This file is inert with a public payload host
 * and can be removed.
 */

add_filter(
	'http_request_host_is_external',
	static function ( $external, $host, $url ) {
		return 'attacker' === strtolower( (string) $host ) ? true : $external;
	},
	10,
	3
);
