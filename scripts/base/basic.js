export function getAllModules() {
	var results = {}
	Process.enumerateModules( {
		onMatch: function (module) {
			results[module['name']] = module['base'];
		},
		onComplete: function () {
		}
	});
	return results;
}