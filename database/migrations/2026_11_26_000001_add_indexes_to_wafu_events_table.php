<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection()
    {
        return config('admin.database.connection') ?: config('database.default');
    }

    public function up(): void
    {
        $connection = $this->getConnection();
        $tableName = config('admin.extensions.wafu.events_table', 'wafu_events');
        $schema = Schema::connection($connection);

        if (!$schema->hasTable($tableName)) {
            return;
        }

        $schema->table($tableName, function (Blueprint $table) use ($schema, $tableName) {
            if (!$schema->hasIndex($tableName, ['created_at'])) {
                $table->index('created_at');
            }
        });
    }

    public function down(): void
    {
        $connection = $this->getConnection();
        $tableName = config('admin.extensions.wafu.events_table', 'wafu_events');
        $schema = Schema::connection($connection);

        if (!$schema->hasTable($tableName)) {
            return;
        }

        $schema->table($tableName, function (Blueprint $table) use ($schema, $tableName) {
            if ($schema->hasIndex($tableName, ['created_at'])) {
                $table->dropIndex([$tableName === 'wafu_events' ? 'created_at' : 'created_at']);
            }
        });
    }
};
