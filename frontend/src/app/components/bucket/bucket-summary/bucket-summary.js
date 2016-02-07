import template from './bucket-summary.html';
import ko from 'knockout';
import numeral from 'numeral';
import style from 'style';
import { formatSize } from 'utils';

class BucketSummrayViewModel {
	constructor({ bucket }) {
		this.dataReady = ko.pureComputed(
			() => !!bucket()
		);

		this.name  = ko.pureComputed(
			() => bucket() && bucket().name
		);

		this.fileCount = ko.pureComputed(
			() => bucket() && bucket().num_objects
		);

		this.fileCountText = ko.pureComputed(
			() => `${this.fileCount() ? numeral(this.fileCount()).format('0,0') : 'No'} files`
		)		
		
		this.total = ko.pureComputed(
			() => bucket() && bucket().storage.used
		);

		this.totalText = ko.pureComputed(
			() => bucket() && formatSize(bucket().storage.total)
		);

		this.free = ko.pureComputed(
			() => bucket() && bucket().storage.free
		);

		this.freeText = ko.pureComputed(
			() => formatSize(this.free())
		);

		this.used = ko.pureComputed(
			() => bucket() && bucket().storage.used
		);

		this.usedText = ko.pureComputed(
			() => bucket() && formatSize(this.used())
		);

		this.gaugeValues = [ 
			{ value: this.used, color: style['text-color6'], emphasize: true },
			{ value: this.free, color: style['text-color4'] }
		]

		this.policy = ko.pureComputed(
			() => bucket() && bucket().tiering
		);

		this.isPolicyModalVisible = ko.observable(false);
		this.isUploadFilesModalVisible = ko.observable(false);
		this.isCloudSyncModalVisible = ko.observable(true);
	}
}

export default {
	viewModel: BucketSummrayViewModel,
	template: template
}