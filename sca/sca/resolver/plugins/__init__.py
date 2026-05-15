from sca.resolver.plugin import register_resolver
from sca.resolver.plugins.npm import NpmResolver
from sca.resolver.plugins.pypi import PypiResolver
from sca.resolver.plugins.maven import MavenResolver
from sca.resolver.plugins.go import GoResolver
from sca.resolver.plugins.swift import SwiftResolver
from sca.resolver.plugins.rust import RustResolver
from sca.resolver.plugins.ruby import RubyResolver
from sca.resolver.plugins.dotnet import DotnetResolver

register_resolver("npm", NpmResolver)
register_resolver("pypi", PypiResolver)
register_resolver("maven", MavenResolver)
register_resolver("go", GoResolver)
register_resolver("swift", SwiftResolver)
register_resolver("rust", RustResolver)
register_resolver("ruby", RubyResolver)
register_resolver("dotnet", DotnetResolver)